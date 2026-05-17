using Synccl.Core.Entities.Enums.KeyWrapping;

namespace Synccl.Core.Entities.Model.Security
{
    public sealed class KeyWrap
    {
        public Guid Id { get; private set; }
        public Guid WrappedKeyId { get; private set; }
        public Guid? WrappingKeyId { get; private set; }

        public KeyWrappingProfile Profile { get; private set; }
        public KeyWrappingMetadata Metadata { get; private set; }

        public byte[] WrappedKey { get; private set; }
        public byte[]? Nonce { get; private set; }
        public byte[]? Salt { get; private set; }
        public byte[]? EphemeralPublicKey { get; private set; }
        public byte[]? Aad { get; private set; }

        public int KeyVersion { get; private set; }
        public DateTime CreatedAtUtc { get; private set; }

        // TPM-specific
        public string? TpmKeyName { get; private set; }
        public byte[]? TpmPolicyDigest { get; private set; }

        // KDF-specific
        public int? Argon2MemoryKiB { get; private set; }
        public int? Argon2Iterations { get; private set; }
        public int? Argon2Parallelism { get; private set; }

        private KeyWrap(
            Guid wrappedKeyId,
            Guid? wrappingKeyId,
            KeyWrappingProfile profile,
            byte[] wrappedKey,
            int keyVersion,
            byte[]? nonce = null,
            byte[]? salt = null,
            byte[]? ephemeralPublicKey = null,
            byte[]? aad = null,
            string? tpmKeyName = null,
            byte[]? tpmPolicyDigest = null,
            int? argon2MemoryKiB = null,
            int? argon2Iterations = null,
            int? argon2Parallelism = null,
            Guid? id = null,
            DateTime? createdAt = null)
        {
            if (wrappedKeyId == Guid.Empty)
                throw new ArgumentException("Wrapped key ID cannot be empty.", nameof(wrappedKeyId));

            if (wrappedKey is null || wrappedKey.Length == 0)
                throw new ArgumentException("Wrapped key cannot be null or empty.", nameof(wrappedKey));

            if (keyVersion <= 0)
                throw new ArgumentException("Key version must be positive.", nameof(keyVersion));

            Id = id ?? Guid.NewGuid();
            WrappedKeyId = wrappedKeyId;
            WrappingKeyId = wrappingKeyId;
            Profile = profile;
            Metadata = KeyWrappingMetadata.From(profile);
            WrappedKey = wrappedKey.ToArray();
            Nonce = nonce?.ToArray();
            Salt = salt?.ToArray();
            EphemeralPublicKey = ephemeralPublicKey?.ToArray();
            Aad = aad?.ToArray();
            KeyVersion = keyVersion;
            CreatedAtUtc = createdAt ?? DateTime.UtcNow;
            TpmKeyName = tpmKeyName;
            TpmPolicyDigest = tpmPolicyDigest?.ToArray();
            Argon2MemoryKiB = argon2MemoryKiB;
            Argon2Iterations = argon2Iterations;
            Argon2Parallelism = argon2Parallelism;
        }

        public static KeyWrap CreateTpmAes128(
            Guid wrappedKeyId,
            byte[] wrappedKey,
            int keyVersion,
            string? tpmKeyName = null,
            byte[]? tpmPolicyDigest = null)
        {
            return new KeyWrap(
                wrappedKeyId,
                wrappingKeyId: null,
                KeyWrappingProfile.TpmAes128,
                wrappedKey,
                keyVersion,
                tpmKeyName: tpmKeyName,
                tpmPolicyDigest: tpmPolicyDigest);
        }

        public static KeyWrap CreateTpmAes256(
            Guid wrappedKeyId,
            byte[] wrappedKey,
            int keyVersion,
            string? tpmKeyName = null,
            byte[]? tpmPolicyDigest = null)
        {
            return new KeyWrap(
                wrappedKeyId,
                wrappingKeyId: null,
                KeyWrappingProfile.TpmAes256,
                wrappedKey,
                keyVersion,
                tpmKeyName: tpmKeyName,
                tpmPolicyDigest: tpmPolicyDigest);
        }

        public static KeyWrap CreatePassphraseArgon2IdXChaCha20Poly1305(
            Guid wrappedKeyId,
            byte[] wrappedKey,
            byte[] nonce,
            byte[] salt,
            int keyVersion,
            int argon2MemoryKiB,
            int argon2Iterations,
            int argon2Parallelism,
            byte[]? aad = null)
        {
            RequireBytes(nonce, nameof(nonce));
            RequireBytes(salt, nameof(salt));

            if (argon2MemoryKiB <= 0)
                throw new ArgumentException("Argon2 memory must be positive.", nameof(argon2MemoryKiB));

            if (argon2Iterations <= 0)
                throw new ArgumentException("Argon2 iterations must be positive.", nameof(argon2Iterations));

            if (argon2Parallelism <= 0)
                throw new ArgumentException("Argon2 parallelism must be positive.", nameof(argon2Parallelism));

            return new KeyWrap(
                wrappedKeyId,
                wrappingKeyId: null,
                KeyWrappingProfile.PassphraseArgon2IdXChaCha20Poly1305,
                wrappedKey,
                keyVersion,
                nonce: nonce,
                salt: salt,
                aad: aad,
                argon2MemoryKiB: argon2MemoryKiB,
                argon2Iterations: argon2Iterations,
                argon2Parallelism: argon2Parallelism);
        }

        public static KeyWrap CreatePublicKeyX25519HkdfXChaCha20Poly1305(
            Guid wrappedKeyId,
            Guid recipientKeyId,
            byte[] wrappedKey,
            byte[] nonce,
            byte[] ephemeralPublicKey,
            int keyVersion,
            byte[]? aad = null)
        {
            if (recipientKeyId == Guid.Empty)
                throw new ArgumentException("Recipient key ID cannot be empty.", nameof(recipientKeyId));

            RequireBytes(nonce, nameof(nonce));
            RequireBytes(ephemeralPublicKey, nameof(ephemeralPublicKey));

            return new KeyWrap(
                wrappedKeyId,
                wrappingKeyId: recipientKeyId,
                KeyWrappingProfile.PublicKeyX25519HkdfXChaCha20Poly1305,
                wrappedKey,
                keyVersion,
                nonce: nonce,
                ephemeralPublicKey: ephemeralPublicKey,
                aad: aad);
        }

        public static KeyWrap CreateParentKeyXChaCha20Poly1305(
            Guid wrappedKeyId,
            Guid parentKeyId,
            byte[] wrappedKey,
            byte[] nonce,
            int keyVersion,
            byte[]? aad = null)
        {
            if (parentKeyId == Guid.Empty)
                throw new ArgumentException("Parent key ID cannot be empty.", nameof(parentKeyId));

            RequireBytes(nonce, nameof(nonce));

            return new KeyWrap(
                wrappedKeyId,
                wrappingKeyId: parentKeyId,
                KeyWrappingProfile.ParentKeyXChaCha20Poly1305,
                wrappedKey,
                keyVersion,
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
                keywrap.KeyVersion,
                nonce: keywrap.Nonce,
                salt: keywrap.Salt,
                ephemeralPublicKey: keywrap.EphemeralPublicKey,
                aad: keywrap.Aad,
                tpmKeyName: keywrap.TpmKeyName,
                tpmPolicyDigest: keywrap.TpmPolicyDigest,
                argon2MemoryKiB: keywrap.Argon2MemoryKiB,
                argon2Iterations: keywrap.Argon2Iterations,
                argon2Parallelism: keywrap.Argon2Parallelism,
                keywrap.Id,
                keywrap.CreatedAtUtc);
        }
    }
}