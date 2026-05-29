using Synccl.Core.Model.Security;

namespace Synccl.Core.Model.EncryptedLocalVault
{
    /// <summary>
    /// An encrypted secret item. The <see cref="Key"/> is a plain-text identifier;
    /// the actual secret is stored as an <see cref="EncryptedDataBlob"/>. Every
    /// copy of the item encryption key is stored as a <see cref="KeyWrap"/> so the
    /// same ciphertext can be unlocked by multiple parties (e.g. device TPM and a
    /// passphrase-derived key).
    /// </summary>
    public sealed class EncryptedLocalItem
    {
        private readonly List<KeyWrap> _wrappedItemKeys;

        public Guid Id { get; private set; }

        /// <summary>Plain-text key name used to look up this item.</summary>
        public string Key { get; private set; }

        /// <summary>Encrypted payload of the secret value.</summary>
        public EncryptedDataBlob Payload { get; private set; }

        /// <summary>Defensive-copy snapshot of all key wraps for this item.</summary>
        public IReadOnlyList<KeyWrap> WrappedItemKeys =>
            _wrappedItemKeys.Select(KeyWrap.From).ToList();

        // ------------------------------------------------------------------ //
        //  Construction
        // ------------------------------------------------------------------ //

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
            _wrappedItemKeys = wraps.Select(KeyWrap.From).ToList();
        }

        /// <summary>Create a brand-new item with a freshly generated ID.</summary>
        public static EncryptedLocalItem Create(
            string key,
            EncryptedDataBlob payload,
            IEnumerable<KeyWrap> wrappedItemKeys)
        {
            if (string.IsNullOrWhiteSpace(key))
                throw new ArgumentException("Item key cannot be null or whitespace.", nameof(key));

            if (payload is null)
                throw new ArgumentNullException(nameof(payload));

            if (wrappedItemKeys is null)
                throw new ArgumentNullException(nameof(wrappedItemKeys));

            var wraps = wrappedItemKeys.ToList();
            if (wraps.Count == 0)
                throw new ArgumentException("Item must have at least one key wrap.", nameof(wrappedItemKeys));

            if (wraps.Any(x => x.WrappedKeyId != payload.EncryptedBy))
                throw new ArgumentException(
                    "All key wraps must wrap the same key that was used to encrypt the payload.",
                    nameof(wrappedItemKeys));

            return new EncryptedLocalItem(Guid.NewGuid(), key, payload, wraps);
        }

        /// <summary>Reconstruct an item from persisted data (used by the mapper).</summary>
        internal static EncryptedLocalItem Reconstruct(
            Guid id,
            string key,
            EncryptedDataBlob payload,
            IEnumerable<KeyWrap> wrappedItemKeys)
        {
            return new EncryptedLocalItem(id, key, payload, wrappedItemKeys);
        }

        /// <summary>Deep-copy an existing item, preserving its ID.</summary>
        public static EncryptedLocalItem From(EncryptedLocalItem item)
        {
            if (item is null)
                throw new ArgumentNullException(nameof(item));

            return new EncryptedLocalItem(
                item.Id,
                item.Key,
                EncryptedDataBlob.From(item.Payload),
                item.WrappedItemKeys.Select(KeyWrap.From));
        }

        // ------------------------------------------------------------------ //
        //  Mutation
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Rename the item's key. The caller is responsible for ensuring
        /// uniqueness within the parent namespace.
        /// </summary>
        public void RenameKey(string newKey)
        {
            if (string.IsNullOrWhiteSpace(newKey))
                throw new ArgumentException("New key cannot be null or whitespace.", nameof(newKey));

            Key = newKey;
        }

        /// <summary>
        /// Replace the payload with a re-encrypted blob that uses the same
        /// item key (same <see cref="EncryptedDataBlob.EncryptedBy"/> GUID).
        /// </summary>
        public void SetPayload(EncryptedDataBlob newPayload)
        {
            if (newPayload is null)
                throw new ArgumentNullException(nameof(newPayload));

            if (newPayload.EncryptedBy != Payload.EncryptedBy)
                throw new InvalidOperationException(
                    "New payload must be encrypted by the same key as the existing payload. " +
                    "Use SetPayloadWithNewKeyWraps to rotate the item key.");

            Payload = EncryptedDataBlob.From(newPayload);
        }

        /// <summary>
        /// Atomically rotate the item key: replace the payload and all key
        /// wraps in one operation. Used during key rotation.
        /// </summary>
        public void SetPayloadWithNewKeyWraps(
            EncryptedDataBlob newPayload,
            IEnumerable<KeyWrap> newKeyWraps)
        {
            if (newPayload is null)
                throw new ArgumentNullException(nameof(newPayload));
            if (newKeyWraps is null)
                throw new ArgumentNullException(nameof(newKeyWraps));

            var wraps = newKeyWraps.ToList();
            if (wraps.Count == 0)
                throw new ArgumentException("At least one key wrap must be provided.", nameof(newKeyWraps));
            if (wraps.Any(x => x.WrappedKeyId != newPayload.EncryptedBy))
                throw new ArgumentException(
                    "All key wraps must wrap the same key that was used to encrypt the new payload.",
                    nameof(newKeyWraps));

            Payload = EncryptedDataBlob.From(newPayload);
            _wrappedItemKeys.Clear();
            _wrappedItemKeys.AddRange(wraps.Select(KeyWrap.From));
        }

        /// <summary>Add a new key wrap (e.g. for a new recipient/device).</summary>
        public void AddKeyWrap(KeyWrap keyWrap)
        {
            if (keyWrap is null)
                throw new ArgumentNullException(nameof(keyWrap));
            if (ContainsKeyWrap(keyWrap.Id))
                throw new InvalidOperationException(
                    $"A key wrap with ID {keyWrap.Id} already exists for this item.");
            if (keyWrap.WrappedKeyId != Payload.EncryptedBy)
                throw new ArgumentException(
                    "The key wrap must wrap the same key that was used to encrypt the payload.",
                    nameof(keyWrap));

            _wrappedItemKeys.Add(KeyWrap.From(keyWrap));
        }

        /// <summary>Remove a key wrap by its ID.</summary>
        public void RemoveKeyWrap(Guid keyWrapId)
        {
            if (_wrappedItemKeys.Count == 1)
                throw new InvalidOperationException("Cannot remove the last key wrap from an item.");

            var wrap = _wrappedItemKeys.FirstOrDefault(w => w.Id == keyWrapId);
            if (wrap is not null)
                _wrappedItemKeys.Remove(wrap);
        }

        // ------------------------------------------------------------------ //
        //  Queries
        // ------------------------------------------------------------------ //

        public bool ContainsKeyWrap(Guid keyWrapId) =>
            _wrappedItemKeys.Any(w => w.Id == keyWrapId);
    }
}