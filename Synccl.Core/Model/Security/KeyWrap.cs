using Synccl.Core.Enums.KeyWrapping;

namespace Synccl.Core.Model.Security
{
    public sealed class KeyWrap
    {
        public Guid Id { get; private set; }
        public Guid WrappedKeyId { get; private set; }
        public Guid? WrappingKeyId { get; private set; }

        public KeyWrappingProfile Profile { get; private set; }
        public KeyWrappingMetadata Metadata { get; private set; }
        public DateTime CreatedAtUtc { get; private set; }

        public byte[] WrappedKey { get; private set; }

        // Symmetric Encryption Specific
        public byte[]? Nonce { get; private set; }
        public byte[]? Aad { get; private set; }

        // TPM specific
        public byte[]? TPMEndorsementKeyHash { get; private set; }
        public TPMKeyBlob? TPMKeyBlob { get; private set; }

        // KDF-specific
        public byte[]? Salt { get; private set; }
        public byte[]? Info { get; private set; }

        // Public key agreement specific
        public byte[]? EphemeralPublicKey { get; private set; }

        // Argon2-specific
        public int? Argon2MemoryKiB { get; private set; }
        public int? Argon2Iterations { get; private set; }

        private KeyWrap(
            Guid wrappedKeyId,
            Guid? wrappingKeyId,
            KeyWrappingProfile profile,
            byte[] wrappedKey,

            byte[]? nonce = null,
            byte[]? aad = null,

            byte[]? tpmEndorsementKeyHash = null,
            TPMKeyBlob? tpmKeyBlob = null,

            byte[]? salt = null,
            byte[]? hkdfInfo = null,

            byte[]? ephemeralPublicKey = null,

            int? argon2MemoryKiB = null,
            int? argon2Iterations = null,

            Guid? id = null,
            DateTime? createdAt = null)
        {
            if (wrappedKeyId == Guid.Empty)
                throw new ArgumentException("Wrapped key ID cannot be empty.", nameof(wrappedKeyId));

            if (wrappedKey is null || wrappedKey.Length == 0)
                throw new ArgumentException("Wrapped key cannot be null or empty.", nameof(wrappedKey));

            Id = id ?? Guid.NewGuid();
            WrappedKeyId = wrappedKeyId;
            WrappingKeyId = wrappingKeyId;
            Profile = profile;
            Metadata = KeyWrappingMetadata.From(profile);
            CreatedAtUtc = createdAt ?? DateTime.UtcNow;

            WrappedKey = wrappedKey.ToArray();

            Nonce = nonce?.ToArray();
            Aad = aad?.ToArray();

            TPMEndorsementKeyHash = tpmEndorsementKeyHash;
            TPMKeyBlob = tpmKeyBlob;

            Salt = salt?.ToArray();
            Info = hkdfInfo?.ToArray();

            EphemeralPublicKey = ephemeralPublicKey?.ToArray();

            Argon2MemoryKiB = argon2MemoryKiB;
            Argon2Iterations = argon2Iterations;
        }

        public static KeyWrap CreateTpmAes128(
            Guid wrappedKeyId,
            byte[] wrappedKey,
            byte[] tpmEndorsementKeyHash,
            TPMKeyBlob tpmKeyBlob)
        {
            return new KeyWrap(
                wrappedKeyId,
                null,
                KeyWrappingProfile.TpmAes128,
                wrappedKey,
                tpmEndorsementKeyHash: tpmEndorsementKeyHash,
                tpmKeyBlob: tpmKeyBlob);
        }

        public static KeyWrap CreateTpmAes256(
            Guid wrappedKeyId,
            byte[] wrappedKey,
            byte[] tpmEndorsementKeyHash,
            TPMKeyBlob tpmKeyBlob)
        {
            return new KeyWrap(
                wrappedKeyId,
                null,
                KeyWrappingProfile.TpmAes256,
                wrappedKey,
                tpmEndorsementKeyHash: tpmEndorsementKeyHash,
                tpmKeyBlob: tpmKeyBlob);
        }

        public static KeyWrap CreatePassphraseArgon2IdXChaCha20Poly1305(
            Guid wrappedKeyId,
            byte[] wrappedKey,
            byte[] nonce,
            byte[] aad,
            byte[] salt,
            int argon2MemoryKiB,
            int argon2Iterations)
        {
            RequireBytes(nonce, nameof(nonce));
            RequireBytes(salt, nameof(salt));

            if (argon2MemoryKiB <= 0)
                throw new ArgumentException("Argon2 memory must be positive.", nameof(argon2MemoryKiB));

            if (argon2Iterations <= 0)
                throw new ArgumentException("Argon2 iterations must be positive.", nameof(argon2Iterations));

            return new KeyWrap(
                wrappedKeyId,
                null,
                KeyWrappingProfile.PassphraseArgon2IdXChaCha20Poly1305,
                wrappedKey,
                nonce: nonce,
                salt: salt,
                aad: aad,
                argon2MemoryKiB: argon2MemoryKiB,
                argon2Iterations: argon2Iterations);
        }

        public static KeyWrap CreatePublicKeyX25519HkdfXChaCha20Poly1305(
            Guid wrappedKeyId,
            byte[] wrappedKey,
            byte[] nonce,
            byte[] aad,
            byte[] salt,
            byte[] info,
            byte[] ephemeralPublicKey)
        {
            RequireBytes(nonce, nameof(nonce));
            RequireBytes(ephemeralPublicKey, nameof(ephemeralPublicKey));

            return new KeyWrap(
                wrappedKeyId,
                null,
                KeyWrappingProfile.PublicKeyX25519HkdfXChaCha20Poly1305,
                wrappedKey,
                nonce: nonce,
                ephemeralPublicKey: ephemeralPublicKey,
                aad: aad,
                salt: salt,
                hkdfInfo: info);
        }

        public static KeyWrap CreateParentKeyXChaCha20Poly1305(
            Guid wrappedKeyId,
            Guid parentKeyId,
            byte[] wrappedKey,
            byte[] nonce,
            byte[] aad)
        {
            if (parentKeyId == Guid.Empty)
                throw new ArgumentException("Parent key ID cannot be empty.", nameof(parentKeyId));

            RequireBytes(nonce, nameof(nonce));

            return new KeyWrap(
                wrappedKeyId,
                wrappingKeyId: parentKeyId,
                KeyWrappingProfile.ParentKeyXChaCha20Poly1305,
                wrappedKey,
                nonce: nonce,
                aad: aad);
        }

        private static void RequireBytes(byte[]? value, string paramName)
        {
            if (value is null || value.Length == 0)
                throw new ArgumentException($"{paramName} cannot be null or empty.", paramName);
        }

        public static KeyWrap From(KeyWrap keywrap)
        {
            return new KeyWrap(
                keywrap.WrappedKeyId,
                keywrap.WrappingKeyId,
                keywrap.Profile,
                keywrap.WrappedKey,
                nonce: keywrap.Nonce,
                aad: keywrap.Aad,
                tpmEndorsementKeyHash: keywrap.TPMEndorsementKeyHash,
                tpmKeyBlob: keywrap.TPMKeyBlob != null ? TPMKeyBlob.From(keywrap.TPMKeyBlob) : null,
                salt: keywrap.Salt,
                hkdfInfo: keywrap.Info,
                ephemeralPublicKey: keywrap.EphemeralPublicKey,
                argon2MemoryKiB: keywrap.Argon2MemoryKiB,
                argon2Iterations: keywrap.Argon2Iterations,
                id: keywrap.Id,
                createdAt: keywrap.CreatedAtUtc);
        }
    }
}