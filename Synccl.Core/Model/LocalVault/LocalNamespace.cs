using Synccl.Core.Error.Exceptions;
using Synccl.Core.Interfaces;

namespace Synccl.Core.Model.LocalVault
{
    public class LocalNamespace : IReadOnlyLocalNamespace
    {
        private readonly Dictionary<string, LocalItem> _items = new();
        public Guid Id { get; private set; }
        public string Name { get; private set; }

        public LocalNamespace(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentException("Namespace name cannot be null or whitespace.", nameof(name));

            Id = Guid.NewGuid();
            Name = name;
        }

        public string this[string key]
        {
            get
            {
                return _items.TryGetValue(key, out var item)
                    ? item.Value
                    : throw new ItemNotFoundInNamespaceException(key, Name);
            }
            set
            {
                if (value is null)
                    throw new ArgumentNullException("Item value cannot be null.", nameof(value));

                if (string.IsNullOrWhiteSpace(key))
                    throw new ArgumentException("Item key cannot be null or whitespace.", nameof(key));

                if (_items.TryGetValue(key, out var item))
                {
                    item.Value = value;
                    return;
                }

                _items.Add(key, LocalItem.From(key, value));
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

        public void Remove(string key)
        {
            _items.Remove(key);
        }
    }
}
