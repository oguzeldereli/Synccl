using Newtonsoft.Json;
using Synccl.Core.Enums;
using Synccl.Core.Error.Exceptions;
using Synccl.Core.Model.Security;

namespace Synccl.Core.Model.EncryptedLocalVault
{
    /// <summary>
    /// Root aggregate for a local-first encrypted secrets vault. A vault
    /// contains one or more <see cref="EncryptedLocalNamespace"/>s (always
    /// at least the default namespace) and zero or more
    /// <see cref="KeyWrap"/>s that protect the vault master key.
    /// </summary>
    public sealed class EncryptedLocalVault
    {
        private readonly List<KeyWrap> _wrappedVaultKeys;

        // Namespaces keyed by name for O(1) lookups.
        private readonly Dictionary<string, EncryptedLocalNamespace> _namespaces;

        public Guid Id { get; private set; }
        public string Name { get; private set; }
        public int Version { get; private set; }
        public string DefaultNamespaceName { get; private set; }
        public EncryptedLocalVaultAccessMode AccessMode { get; private set; }

        /// <summary>Defensive-copy snapshot of the vault master-key wraps.</summary>
        public IReadOnlyList<KeyWrap> WrappedVaultKeys =>
            _wrappedVaultKeys.Select(KeyWrap.From).ToList();

        /// <summary>Defensive-copy snapshot of all namespaces in this vault.</summary>
        public IReadOnlyList<EncryptedLocalNamespace> Namespaces =>
            _namespaces.Values.Select(EncryptedLocalNamespace.From).ToList();

        // ------------------------------------------------------------------ //
        //  Construction
        // ------------------------------------------------------------------ //

        private EncryptedLocalVault(
            Guid id,
            string name,
            string defaultNamespaceName,
            int version,
            EncryptedLocalVaultAccessMode accessMode,
            IEnumerable<KeyWrap> wrappedVaultKeys,
            IEnumerable<EncryptedLocalNamespace> namespaces)
        {
            if (id == Guid.Empty)
                throw new ArgumentException("Vault ID cannot be empty.", nameof(id));

            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Vault name cannot be null or whitespace.", nameof(name));

            if (string.IsNullOrWhiteSpace(defaultNamespaceName))
                throw new ArgumentException("Default namespace name cannot be null or whitespace.", nameof(defaultNamespaceName));

            if (version < 1)
                throw new ArgumentOutOfRangeException(nameof(version), "Version must be at least 1.");

            Id = id;
            Name = name;
            DefaultNamespaceName = defaultNamespaceName;
            Version = version;
            AccessMode = accessMode;

            _wrappedVaultKeys = (wrappedVaultKeys ?? Enumerable.Empty<KeyWrap>())
                .Select(KeyWrap.From).ToList();

            _namespaces = (namespaces ?? Enumerable.Empty<EncryptedLocalNamespace>())
                .ToDictionary(ns => ns.Name, EncryptedLocalNamespace.From);
        }

        /// <summary>
        /// Create a brand-new vault. The default namespace is seeded with the
        /// supplied <paramref name="defaultNamespaceKeyWraps"/>; vault-level
        /// key wraps can be added later via <see cref="AddVaultKeyWrap"/>.
        /// </summary>
        public static EncryptedLocalVault CreateNew(
            string name,
            string defaultNamespaceName,
            IEnumerable<KeyWrap> defaultNamespaceKeyWraps)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Vault name cannot be null or whitespace.", nameof(name));

            if (string.IsNullOrWhiteSpace(defaultNamespaceName))
                throw new ArgumentException("Default namespace name cannot be null or whitespace.", nameof(defaultNamespaceName));

            var defaultNs = EncryptedLocalNamespace.CreateNew(defaultNamespaceName, defaultNamespaceKeyWraps);

            return new EncryptedLocalVault(
                Guid.NewGuid(),
                name,
                defaultNamespaceName,
                version: 1,
                EncryptedLocalVaultAccessMode.MountedDeviceBound,
                wrappedVaultKeys: [],
                namespaces: [defaultNs]);
        }

        /// <summary>
        /// Convenience overload that creates a vault without any initial
        /// namespace key wraps (wraps are added later, e.g. after TPM init).
        /// </summary>
        public static EncryptedLocalVault CreateNew(string name, string defaultNamespaceName = "default")
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Vault name cannot be null or whitespace.", nameof(name));

            if (string.IsNullOrWhiteSpace(defaultNamespaceName))
                throw new ArgumentException("Default namespace name cannot be null or whitespace.", nameof(defaultNamespaceName));

            return new EncryptedLocalVault(
                Guid.NewGuid(),
                name,
                defaultNamespaceName,
                version: 1,
                EncryptedLocalVaultAccessMode.MountedDeviceBound,
                wrappedVaultKeys: [],
                namespaces: []);
        }

        /// <summary>
        /// Reconstruct a vault from persisted data (used by the mapper).
        /// Allows an empty key-wrap list so a freshly-created vault with no wraps yet can be loaded.
        /// </summary>
        internal static EncryptedLocalVault Reconstruct(
            Guid id,
            string name,
            string defaultNamespaceName,
            int version,
            EncryptedLocalVaultAccessMode accessMode,
            IEnumerable<KeyWrap> wrappedVaultKeys,
            IEnumerable<EncryptedLocalNamespace> namespaces)
        {
            // Bypass the "at least one key wrap" requirement that CreateNew doesn't enforce either.
            var vault = new EncryptedLocalVault(id, name, defaultNamespaceName, version, accessMode,
                wrappedVaultKeys, namespaces);
            return vault;
        }

        /// <summary>Deep-copy an existing vault, preserving its ID and version.</summary>
        public static EncryptedLocalVault From(EncryptedLocalVault vault)
        {
            if (vault is null)
                throw new ArgumentNullException(nameof(vault));

            return new EncryptedLocalVault(
                vault.Id,
                vault.Name,
                vault.DefaultNamespaceName,
                vault.Version,
                vault.AccessMode,
                vault.WrappedVaultKeys,
                vault.Namespaces);
        }

        // ------------------------------------------------------------------ //
        //  Vault metadata
        // ------------------------------------------------------------------ //

        /// <summary>Rename the vault.</summary>
        public void Rename(string newName)
        {
            if (string.IsNullOrWhiteSpace(newName))
                throw new ArgumentException("New name cannot be null or whitespace.", nameof(newName));

            Name = newName;
        }

        /// <summary>Bump the schema/format version (e.g. after a key rotation).</summary>
        public void IncrementVersion() => Version++;

        /// <summary>Change the access mode (e.g. after protect/unprotect).</summary>
        public void SetAccessMode(EncryptedLocalVaultAccessMode mode) => AccessMode = mode;

        // ------------------------------------------------------------------ //
        //  Namespace management
        // ------------------------------------------------------------------ //

        private EncryptedLocalNamespace GetNamespaceOrThrow(string? nsName)
        {
            var name = nsName ?? DefaultNamespaceName;
            if (_namespaces.TryGetValue(name, out var ns))
                return ns;
            throw new NamespaceNotFoundException(name, Name);
        }

        /// <summary>
        /// Add a new, empty namespace that has already been initialised with
        /// its own key wraps.
        /// </summary>
        public void AddNamespace(EncryptedLocalNamespace ns)
        {
            if (ns is null)
                throw new ArgumentNullException(nameof(ns));

            if (_namespaces.ContainsKey(ns.Name))
                throw new NamespaceAlreadyExistsException(ns.Name, Name);

            _namespaces[ns.Name] = EncryptedLocalNamespace.From(ns);
        }

        /// <summary>Remove a namespace by name. The default namespace cannot be removed.</summary>
        public void RemoveNamespace(string nsName)
        {
            if (string.IsNullOrWhiteSpace(nsName))
                throw new ArgumentException("Namespace name cannot be null or whitespace.", nameof(nsName));

            if (nsName == DefaultNamespaceName)
                throw new VaultDefaultNamespaceCannotBeRemoved(DefaultNamespaceName, Name);

            if (!_namespaces.Remove(nsName))
                throw new NamespaceNotFoundException(nsName, Name);
        }

        public bool ContainsNamespace(string nsName) => _namespaces.ContainsKey(nsName);

        public IReadOnlyList<string> GetNamespaceNames() => _namespaces.Keys.ToList();

        /// <summary>Get a defensive copy of the named namespace (or the default namespace).</summary>
        public EncryptedLocalNamespace GetNamespace(string? nsName = null) =>
            EncryptedLocalNamespace.From(GetNamespaceOrThrow(nsName));

        /// <summary>
        /// Replace an existing namespace (by name) with the provided instance.
        /// Used internally by the crypto service during key rotation.
        /// </summary>
        internal void ReplaceNamespace(EncryptedLocalNamespace ns)
        {
            if (ns is null) throw new ArgumentNullException(nameof(ns));
            if (!_namespaces.ContainsKey(ns.Name))
                throw new NamespaceNotFoundException(ns.Name, Name);
            _namespaces[ns.Name] = EncryptedLocalNamespace.From(ns);
        }

        /// <summary>
        /// Upsert (add if missing, replace if existing) a namespace. Used during vault
        /// reconstruction after bulk operations.
        /// </summary>
        internal void UpsertNamespace(EncryptedLocalNamespace ns)
        {
            if (ns is null) throw new ArgumentNullException(nameof(ns));
            _namespaces[ns.Name] = EncryptedLocalNamespace.From(ns);
        }

        // ------------------------------------------------------------------ //
        //  Item forwarding helpers
        // ------------------------------------------------------------------ //

        /// <summary>Set (add or overwrite) an item in a namespace.</summary>
        public void SetItem(string key, EncryptedLocalItem item, string? nsName = null) =>
            GetNamespaceOrThrow(nsName).SetOrReplaceItem(item);

        /// <summary>Get a defensive copy of an item from a namespace.</summary>
        public EncryptedLocalItem GetItem(string key, string? nsName = null) =>
            GetNamespaceOrThrow(nsName).GetItem(key);

        public bool TryGetItem(string key, out EncryptedLocalItem? item, string? nsName = null)
        {
            var nsExists = _namespaces.TryGetValue(nsName ?? DefaultNamespaceName, out var ns);
            if (!nsExists || ns is null)
            {
                item = null;
                return false;
            }
            return ns.TryGetItem(key, out item);
        }

        /// <summary>Remove an item from a namespace.</summary>
        public void RemoveItem(string key, string? nsName = null) =>
            GetNamespaceOrThrow(nsName).RemoveItem(key);

        public bool ContainsItem(string key, string? nsName = null)
        {
            var nsExists = _namespaces.TryGetValue(nsName ?? DefaultNamespaceName, out var ns);
            return nsExists && ns is not null && ns.ContainsItem(key);
        }

        /// <summary>List the plain-text item keys in a namespace.</summary>
        public IReadOnlyList<string> ListItemKeys(string? nsName = null) =>
            GetNamespaceOrThrow(nsName).GetItemKeys();

        // ------------------------------------------------------------------ //
        //  Vault key-wrap management
        // ------------------------------------------------------------------ //

        /// <summary>Add a key wrap for the vault master key.</summary>
        public void AddVaultKeyWrap(KeyWrap keyWrap)
        {
            if (keyWrap is null)
                throw new ArgumentNullException(nameof(keyWrap));

            if (_wrappedVaultKeys.Count > 0)
            {
                var existingKeyId = _wrappedVaultKeys[0].WrappedKeyId;
                if (keyWrap.WrappedKeyId != existingKeyId)
                    throw new ArgumentException(
                        "The key wrap must wrap the same vault master key as the existing wraps.",
                        nameof(keyWrap));
            }

            if (_wrappedVaultKeys.Any(kw => kw.Id == keyWrap.Id))
                throw new InvalidOperationException(
                    $"A vault key wrap with ID {keyWrap.Id} already exists.");

            _wrappedVaultKeys.Add(KeyWrap.From(keyWrap));
        }

        /// <summary>Remove a vault-level key wrap by its ID.</summary>
        public void RemoveVaultKeyWrap(Guid keyWrapId)
        {
            if (_wrappedVaultKeys.Count == 1)
                throw new InvalidOperationException("Cannot remove the last vault key wrap.");

            var wrap = _wrappedVaultKeys.FirstOrDefault(kw => kw.Id == keyWrapId);
            if (wrap is not null)
                _wrappedVaultKeys.Remove(wrap);
        }

        /// <summary>
        /// Atomically replace all vault-level key wraps. Used during vault
        /// master key rotation.
        /// </summary>
        public void ReplaceVaultKeyWraps(IEnumerable<KeyWrap> newKeyWraps)
        {
            if (newKeyWraps is null)
                throw new ArgumentNullException(nameof(newKeyWraps));

            var wraps = newKeyWraps.ToList();
            if (wraps.Count == 0)
                throw new ArgumentException("At least one key wrap must be provided.", nameof(newKeyWraps));

            if (wraps.Count > 1)
            {
                var wrappedKeyId = wraps[0].WrappedKeyId;
                if (wraps.Any(w => w.WrappedKeyId != wrappedKeyId))
                    throw new ArgumentException("All key wraps must wrap the same vault master key.", nameof(newKeyWraps));
            }

            _wrappedVaultKeys.Clear();
            _wrappedVaultKeys.AddRange(wraps.Select(KeyWrap.From));
        }

        // ------------------------------------------------------------------ //
        //  Serialization
        // ------------------------------------------------------------------ //

        public string ToJson() => JsonConvert.SerializeObject(this);
    }
}
