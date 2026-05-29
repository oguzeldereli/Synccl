namespace Synccl.Core.Persistence
{
    /// <summary>
    /// The algorithm used to encrypt a portable (unmounted) vault file.
    /// </summary>
    public enum UnmountedVaultEncryption : byte
    {
        /// <summary>Passphrase → Argon2id → XChaCha20-Poly1305.</summary>
        PassphraseArgon2IdXChaCha20Poly1305 = 1,

        /// <summary>X25519 key agreement → HKDF-SHA256 → XChaCha20-Poly1305.</summary>
        PublicKeyX25519HkdfXChaCha20Poly1305 = 2,
    }

    /// <summary>
    /// Binary envelope written to a <c>.vault.json.unmounted</c> file.
    ///
    /// Layout (all lengths are fixed-size unless noted):
    /// <code>
    ///   [ 4 bytes  ] magic  = 0x53 0x59 0x43 0x4C  ("SYCL")
    ///   [ 1 byte   ] file format version  = 0x01
    ///   [ 1 byte   ] UnmountedVaultEncryption algorithm tag
    ///   --- passphrase scheme (tag=1) ---
    ///   [ 16 bytes ] Argon2id salt
    ///   [ 24 bytes ] XChaCha20-Poly1305 nonce
    ///   [ 4 bytes  ] ciphertext length (little-endian uint32)
    ///   [ n bytes  ] ciphertext  (includes 16-byte Poly1305 MAC at the end)
    ///   --- pubkey scheme (tag=2) ---
    ///   [ 32 bytes ] ephemeral X25519 public key
    ///   [ 16 bytes ] HKDF salt
    ///   [ 24 bytes ] XChaCha20-Poly1305 nonce
    ///   [ 4 bytes  ] ciphertext length
    ///   [ n bytes  ] ciphertext
    /// </code>
    /// </summary>
    public sealed class UnmountedVaultFile
    {
        public static readonly byte[] Magic = [0x53, 0x59, 0x43, 0x4C]; // "SYCL"
        public const byte FormatVersion = 0x01;

        public UnmountedVaultEncryption Algorithm { get; init; }

        // Passphrase scheme
        public byte[]? Argon2Salt { get; init; }

        // Pubkey scheme
        public byte[]? EphemeralPublicKey { get; init; }
        public byte[]? HkdfSalt { get; init; }

        // Both schemes
        public byte[] Nonce { get; init; } = [];
        public byte[] Ciphertext { get; init; } = [];
    }
}
