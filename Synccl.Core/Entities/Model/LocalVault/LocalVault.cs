using Synccl.Core.Entities.Enums;
using Synccl.Core.Error.Exceptions;

namespace Synccl.Core.Entities.Model.Vault
{
    public class LocalVault
    {
        private readonly Dictionary<string, LocalNamespace> _namespaces = new();
        public Guid Id { get; private set; }
        public string Name { get; private set; }
        public int Version { get; private set; }
        public string DefaultNamespace { get; private set; } = "default";

        public LocalVault(Guid id, int version, string name, string defaultNamespace = "default")
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Vault name cannot be null or whitespace.", nameof(name));

            if (string.IsNullOrWhiteSpace(defaultNamespace))
                throw new ArgumentException("Default namespace cannot be null or whitespace.", nameof(defaultNamespace));

            Id = id;
            Version = version;
            Name = name;
            DefaultNamespace = defaultNamespace;

            _namespaces.Add(DefaultNamespace, new LocalNamespace(DefaultNamespace));
        }
        
        private LocalNamespace GetNamespaceOrDefault(string? nsName) => _namespaces.TryGetValue(nsName ?? DefaultNamespace, out var ns)
            ? ns
            : throw new NamespaceNotFoundException(nsName ?? DefaultNamespace, Name);

        public string this[string key, string? nsName = null]
        {
            get
            {
                var ns = GetNamespaceOrDefault(nsName);
                return ns[key];
            }
            set
            {
                var ns = GetNamespaceOrDefault(nsName);
                ns[key] = value;
            }
        }

        public LocalNamespaceSnapshot GetNamespaceSnapshot(string nsName)
        {
            var ns = GetNamespaceOrDefault(nsName);
            return LocalNamespaceSnapshot.From(ns);
        }

        public IReadOnlyDictionary<string, LocalNamespaceSnapshot> GetNamespaceSnapshots()
        {
            return _namespaces.ToDictionary(entry => entry.Key, entry => LocalNamespaceSnapshot.From(entry.Value));
        }

        public void AddNamespace(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Namespace name cannot be null or whitespace.", nameof(name));
            if (_namespaces.ContainsKey(name))
                throw new NamespaceAlreadyExistsException(name, Name);
            _namespaces.Add(name, new LocalNamespace(name));
        }

        public void RemoveNamespace(string nsName)
        {
            if (nsName == DefaultNamespace)
                throw new VaultDefaultNamespaceCannotBeRemoved(DefaultNamespace, Name);
            if (!_namespaces.ContainsKey(nsName))
                throw new NamespaceNotFoundException(nsName, Name);
            _namespaces.Remove(nsName);
        }

        public bool ContainsNamespace(string nsName)
        {
            return _namespaces.ContainsKey(nsName);
        }

        public void SetItem(string key, string value, string? nsName = null)
        {
            this[key, nsName] = value;
        }

        public string GetItem(string key, string? nsName = null)
        {
            return this[key, nsName];
        }

        public void RemoveItem(string key, string? nsName = null)
        {
            var ns = GetNamespaceOrDefault(nsName);
            ns.Remove(key);
        }

        public bool TryGetItem(string key, out string? value, string? nsName = null)
        {
            var nsExists = _namespaces.TryGetValue(nsName ?? DefaultNamespace, out var ns);
            if (!nsExists || ns == null)
            {
                value = null;
                return false;
            }

            return ns.TryGet(key, out value);
        }

        public bool ContainsKey(string key, string? nsName = null)
        {
            var nsExists = _namespaces.TryGetValue(nsName ?? DefaultNamespace, out var ns);
            if (!nsExists || ns == null)
                return false;
            return ns.ContainsKey(key);
        }
    }
}
