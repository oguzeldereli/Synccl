using Synccl.Core.Entities.Interfaces;
using Synccl.Core.Error.Exceptions;

namespace Synccl.Core.Entities.Model.Vault
{
    public class LocalNamespaceSnapshot : IReadOnlyLocalNamespace
    {
        private readonly IReadOnlyDictionary<string, LocalItem> _items;
        public Guid Id { get; private set; }
        public string Name { get; private set; }

        private LocalNamespaceSnapshot(Guid id, string name, IReadOnlyDictionary<string, LocalItem> items)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Namespace name cannot be null or whitespace.", nameof(name));

            Id = id;
            Name = name;
            _items = items;
        }

        public static LocalNamespaceSnapshot From(LocalNamespace ns)
        {
            var snapshot = new LocalNamespaceSnapshot(ns.Id, ns.Name, ns.GetItems());
            return snapshot;
        }

        public string this[string key]
        {
            get
            {
                return _items.TryGetValue(key, out var item)
                    ? item.Value
                    : throw new ItemNotFoundInNamespaceException(key, Name);
            }
        }

        public IReadOnlyDictionary<string, LocalItem> GetItems()
        {
            return _items.ToDictionary(entry => entry.Key, entry => LocalItem.From(entry.Value));
        }

        public bool TryGet(string key, out string? value)
        {
            var itemExists = _items.TryGetValue(key, out var item);
            if (itemExists && item != null)
            {
                value = item.Value;
                return true;
            }

            value = null;
            return false;
        }

        public bool ContainsKey(string key)
        {
            return _items.ContainsKey(key);
        }
    }
}
