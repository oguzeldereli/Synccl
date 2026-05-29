using Synccl.Core.Error.Exceptions;
using Synccl.Core.Model.Security;

namespace Synccl.Core.Model.EncryptedLocalVault
{
    /// <summary>
    /// An encrypted namespace groups a set of <see cref="EncryptedLocalItem"/>s
    /// under a shared namespace key. The namespace key itself is stored
    /// as one or more <see cref="KeyWrap"/>s so it can be unlocked by
    /// different parties (device TPM, passphrase, etc.).
    /// </summary>
    public sealed class EncryptedLocalNamespace
    {
        private readonly List<KeyWrap> _wrappedNamespaceKeys;

        // Items are keyed by their plain-text Key for O(1) lookups.
        private readonly Dictionary<string, EncryptedLocalItem> _items;

        public Guid Id { get; private set; }
        public string Name { get; private set; }

        /// <summary>Defensive-copy snapshot of the namespace key wraps.</summary>
        public IReadOnlyList<KeyWrap> WrappedNamespaceKeys =>
            _wrappedNamespaceKeys.Select(KeyWrap.From).ToList();

        /// <summary>Defensive-copy snapshot of all items in this namespace.</summary>
        public IReadOnlyList<EncryptedLocalItem> EncryptedItems =>
            _items.Values.Select(EncryptedLocalItem.From).ToList();

        // ------------------------------------------------------------------ //
        //  Construction
        // ------------------------------------------------------------------ //

        private EncryptedLocalNamespace(
            Guid id,
            string name,
            IEnumerable<KeyWrap> wrappedNamespaceKeys,
            IEnumerable<EncryptedLocalItem> items)
        {
            if (id == Guid.Empty)
                throw new ArgumentException("Namespace ID cannot be empty.", nameof(id));

            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Namespace name cannot be null or whitespace.", nameof(name));

            if (wrappedNamespaceKeys is null)
                throw new ArgumentNullException(nameof(wrappedNamespaceKeys));

            var wraps = wrappedNamespaceKeys.ToList();
            if (wraps.Count == 0)
                throw new ArgumentException("Namespace must have at least one key wrap.", nameof(wrappedNamespaceKeys));

            var wrappedKeyId = wraps[0].WrappedKeyId;
            if (wraps.Any(w => w.WrappedKeyId != wrappedKeyId))
                throw new ArgumentException("All key wraps must wrap the same namespace key.", nameof(wrappedNamespaceKeys));

            Id = id;
            Name = name;
            _wrappedNamespaceKeys = wraps.Select(KeyWrap.From).ToList();

            _items = (items ?? Enumerable.Empty<EncryptedLocalItem>())
                .ToDictionary(i => i.Key, EncryptedLocalItem.From);
        }

        /// <summary>Create a brand-new namespace with a freshly generated ID.</summary>
        public static EncryptedLocalNamespace CreateNew(string name, IEnumerable<KeyWrap> keyWraps)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Namespace name cannot be null or whitespace.", nameof(name));

            if (keyWraps is null)
                throw new ArgumentNullException(nameof(keyWraps));

            var wraps = keyWraps.ToList();
            if (wraps.Count == 0)
                throw new ArgumentException("At least one key wrap must be provided.", nameof(keyWraps));

            var wrappedKeyId = wraps[0].WrappedKeyId;
            if (wraps.Any(w => w.WrappedKeyId != wrappedKeyId))
                throw new ArgumentException("All key wraps must wrap the same namespace key.", nameof(keyWraps));

            return new EncryptedLocalNamespace(Guid.NewGuid(), name, wraps, []);
        }

        /// <summary>Reconstruct a namespace from persisted data (used by the mapper).</summary>
        internal static EncryptedLocalNamespace Reconstruct(
            Guid id,
            string name,
            IEnumerable<KeyWrap> wrappedNamespaceKeys,
            IEnumerable<EncryptedLocalItem> items)
        {
            return new EncryptedLocalNamespace(id, name, wrappedNamespaceKeys, items);
        }

        /// <summary>Deep-copy an existing namespace, preserving its ID.</summary>
        public static EncryptedLocalNamespace From(EncryptedLocalNamespace ns)
        {
            if (ns is null)
                throw new ArgumentNullException(nameof(ns));

            return new EncryptedLocalNamespace(
                ns.Id,
                ns.Name,
                ns.WrappedNamespaceKeys,
                ns.EncryptedItems);
        }

        // ------------------------------------------------------------------ //
        //  Namespace metadata
        // ------------------------------------------------------------------ //

        /// <summary>Rename the namespace. Uniqueness within the vault is the caller's concern.</summary>
        public void Rename(string newName)
        {
            if (string.IsNullOrWhiteSpace(newName))
                throw new ArgumentException("New name cannot be null or whitespace.", nameof(newName));

            Name = newName;
        }

        // ------------------------------------------------------------------ //
        //  Item management
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Add a new item. Throws if an item with the same key already exists.
        /// Use <see cref="SetOrReplaceItem"/> to upsert.
        /// </summary>
        public void AddItem(EncryptedLocalItem item)
        {
            if (item is null)
                throw new ArgumentNullException(nameof(item));

            if (_items.ContainsKey(item.Key))
                throw new InvalidOperationException(
                    $"An item with key '{item.Key}' already exists in namespace '{Name}'. " +
                    "Use SetOrReplaceItem to overwrite it.");

            _items[item.Key] = EncryptedLocalItem.From(item);
        }

        /// <summary>Add or overwrite the item with the given key.</summary>
        public void SetOrReplaceItem(EncryptedLocalItem item)
        {
            if (item is null)
                throw new ArgumentNullException(nameof(item));

            _items[item.Key] = EncryptedLocalItem.From(item);
        }

        /// <summary>Remove an item by its plain-text key. Throws if not found.</summary>
        public void RemoveItem(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("Key cannot be null or whitespace.", nameof(key));

            if (!_items.Remove(key))
                throw new ItemNotFoundInNamespaceException(key, Name);
        }

        /// <summary>Get a defensive copy of the item with the given key.</summary>
        public EncryptedLocalItem GetItem(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("Key cannot be null or whitespace.", nameof(key));

            if (!_items.TryGetValue(key, out var item))
                throw new ItemNotFoundInNamespaceException(key, Name);

            return EncryptedLocalItem.From(item);
        }

        public bool TryGetItem(string key, out EncryptedLocalItem? item)
        {
            if (_items.TryGetValue(key, out var found))
            {
                item = EncryptedLocalItem.From(found);
                return true;
            }

            item = null;
            return false;
        }

        public bool ContainsItem(string key) => _items.ContainsKey(key);

        /// <summary>
        /// Returns a snapshot of all item keys (plain-text names) in this namespace.
        /// </summary>
        public IReadOnlyList<string> GetItemKeys() => _items.Keys.ToList();

        // ------------------------------------------------------------------ //
        //  Key-wrap management
        // ------------------------------------------------------------------ //

        /// <summary>Add a new key wrap for an additional recipient/device.</summary>
        public void AddKeyWrap(KeyWrap keyWrap)
        {
            if (keyWrap is null)
                throw new ArgumentNullException(nameof(keyWrap));

            var existingKeyId = _wrappedNamespaceKeys[0].WrappedKeyId;
            if (keyWrap.WrappedKeyId != existingKeyId)
                throw new ArgumentException(
                    "The key wrap must wrap the same namespace key as the existing wraps.",
                    nameof(keyWrap));

            if (_wrappedNamespaceKeys.Any(kw => kw.Id == keyWrap.Id))
                throw new InvalidOperationException(
                    $"A key wrap with ID {keyWrap.Id} already exists in this namespace.");

            _wrappedNamespaceKeys.Add(KeyWrap.From(keyWrap));
        }

        /// <summary>Remove a key wrap by its ID.</summary>
        public void RemoveKeyWrap(Guid keyWrapId)
        {
            if (_wrappedNamespaceKeys.Count == 1)
                throw new InvalidOperationException("Cannot remove the last key wrap from the namespace.");

            var wrap = _wrappedNamespaceKeys.FirstOrDefault(kw => kw.Id == keyWrapId);
            if (wrap is not null)
                _wrappedNamespaceKeys.Remove(wrap);
        }

        /// <summary>
        /// Atomically replace all namespace key wraps. Used during key rotation
        /// when the namespace key itself changes.
        /// </summary>
        public void ReplaceKeyWraps(IEnumerable<KeyWrap> newKeyWraps)
        {
            if (newKeyWraps is null)
                throw new ArgumentNullException(nameof(newKeyWraps));

            var wraps = newKeyWraps.ToList();
            if (wraps.Count == 0)
                throw new ArgumentException("At least one key wrap must be provided.", nameof(newKeyWraps));

            var wrappedKeyId = wraps[0].WrappedKeyId;
            if (wraps.Any(w => w.WrappedKeyId != wrappedKeyId))
                throw new ArgumentException("All key wraps must wrap the same namespace key.", nameof(newKeyWraps));

            _wrappedNamespaceKeys.Clear();
            _wrappedNamespaceKeys.AddRange(wraps.Select(KeyWrap.From));
        }

        // ------------------------------------------------------------------ //
        //  Serialization
        // ------------------------------------------------------------------ //

        public string ToJson() => Newtonsoft.Json.JsonConvert.SerializeObject(this);
    }
}
