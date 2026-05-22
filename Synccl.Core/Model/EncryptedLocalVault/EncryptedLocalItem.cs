using Synccl.Core.Model.Security;

namespace Synccl.Core.Model.EncryptedLocalVault
{
    public sealed class EncryptedLocalItem
    {
        private readonly List<KeyWrap> _wrappedItemKeys;

        public Guid Id { get; private set; }
        public string Key { get; private set; }
        public EncryptedDataBlob Payload { get; private set; }
        public IReadOnlyList<KeyWrap> WrappedItemKeys =>
            _wrappedItemKeys.Select(KeyWrap.From).ToList();

        private EncryptedLocalItem(
            Guid id,
            string key,
            EncryptedDataBlob payload,
            IEnumerable<KeyWrap> wrappedItemKeys)
        {
            if (id == Guid.Empty)
                throw new ArgumentException("Item ID cannot be empty.", nameof(id));

            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("Item key cannot be null or whitespace.", nameof(key));

            if (payload is null)
                throw new ArgumentNullException(nameof(payload));

            if (wrappedItemKeys is null)
                throw new ArgumentNullException(nameof(wrappedItemKeys));

            var wraps = wrappedItemKeys.ToList();

            if (wraps.Count == 0)
                throw new ArgumentException("Item must have at least one key wrap.", nameof(wrappedItemKeys));

            Id = id;
            Key = key;
            Payload = EncryptedDataBlob.From(payload);
            _wrappedItemKeys = wraps;
        }

        public static EncryptedLocalItem Create(
            Guid id,
            string key,
            EncryptedDataBlob payload,
            IEnumerable<KeyWrap> wrappedItemKeys)
        {
            return new EncryptedLocalItem(id, key, payload, wrappedItemKeys);
        }

        public void SetPayload(EncryptedDataBlob newPayload)
        {
            if (newPayload is null)
                throw new ArgumentNullException(nameof(newPayload));
            Payload = EncryptedDataBlob.From(newPayload);
        }

        public void AddKeyWrap(KeyWrap keyWrap)
        {
            if (keyWrap is null)
                throw new ArgumentNullException(nameof(keyWrap));
            if (ContainsKeyWrap(keyWrap.Id))
                throw new InvalidOperationException($"A key wrap with ID {keyWrap.Id} already exists for this item.");
            _wrappedItemKeys.Add(keyWrap);
        }

        public void RemoveKeyWrap(Guid keyWrapId)
        {
            if (_wrappedItemKeys.Count == 1)
                throw new InvalidOperationException("Cannot remove the last key wrap from an item.");
            var wrapToRemove = _wrappedItemKeys.FirstOrDefault(wrap => wrap.Id == keyWrapId);
            if (wrapToRemove != null)
            {
                _wrappedItemKeys.Remove(wrapToRemove);
            }
        }

        public bool ContainsKeyWrap(Guid keyWrapId)
        {
            return _wrappedItemKeys.Any(wrap => wrap.Id == keyWrapId);
        }
    }
}