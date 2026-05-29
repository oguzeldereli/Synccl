using Sodium;
using Synccl.Core.Security;
using System.Security.Cryptography;
using System.Text;

namespace Synccl.Core.Persistence
{
    /// <summary>
    /// Encrypts and decrypts the portable <c>.vault.json.unmounted</c> file.
    ///
    /// Two schemes are supported:
    /// <list type="bullet">
    ///   <item>Passphrase → Argon2id (32-byte key) → XChaCha20-Poly1305</item>
    ///   <item>X25519 public key → ECDH shared secret → HKDF-SHA256 (32-byte key) → XChaCha20-Poly1305</item>
    /// </list>
    /// </summary>
    public static class UnmountedVaultSerializer
    {
        private const string HkdfInfo = "synccl-unmounted-vault-file-encryption-v1";

        // ------------------------------------------------------------------ //
        //  Write
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Encrypts <paramref name="plaintextJson"/> using the passphrase path and
        /// writes a <c>.vault.json.unmounted</c> file to <paramref name="outputPath"/>.
        /// </summary>
        public static void EncryptWithPassphrase(string plaintextJson, string outputPath, byte[] passphrase)
        {
            var salt = new byte[16];
            RandomNumberGenerator.Fill(salt);

            // Derive a 32-byte key via Argon2id.
            var key = PasswordHash.ArgonHashBinary(
                password: passphrase,
                salt: salt,
                opsLimit: 4,
                memLimit: 1 << 28,
                outputLength: 32);

            try
            {
                var nonce = new byte[24];
                RandomNumberGenerator.Fill(nonce);

                var plaintext = Encoding.UTF8.GetBytes(plaintextJson);
                var aad = BuildAad(UnmountedVaultEncryption.PassphraseArgon2IdXChaCha20Poly1305);
                var ciphertext = SecretAeadXChaCha20Poly1305.Encrypt(plaintext, nonce, key, aad);

                var envelope = new UnmountedVaultFile
                {
                    Algorithm = UnmountedVaultEncryption.PassphraseArgon2IdXChaCha20Poly1305,
                    Argon2Salt = salt,
                    Nonce = nonce,
                    Ciphertext = ciphertext,
                };

                WriteFile(outputPath, envelope);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }

        /// <summary>
        /// Encrypts <paramref name="plaintextJson"/> using the X25519 public-key path and
        /// writes a <c>.vault.json.unmounted</c> file to <paramref name="outputPath"/>.
        /// The caller supplies the recipient's raw 32-byte X25519 private key (from which
        /// the public key is derived) OR the raw 32-byte public key directly.
        /// </summary>
        public static void EncryptWithPublicKey(string plaintextJson, string outputPath, byte[] recipientPublicKey)
        {
            // ECDH: ephemeral key pair × recipient public key → shared secret.
            var sharedSecret = KeyAgreementManager.GetSharedSecretWithEphemeralPublicKey(
                Enums.KeyWrapping.KeyWrappingAgreementAlgorithm.X25519,
                recipientPublicKey,
                out var ephemeralPublicKey);

            try
            {
                var hkdfSalt = new byte[16];
                RandomNumberGenerator.Fill(hkdfSalt);

                // Derive 32-byte key via HKDF-SHA256.
                var infoBytes = Encoding.UTF8.GetBytes(HkdfInfo);
                var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32, hkdfSalt, infoBytes);

                try
                {
                    var nonce = new byte[24];
                    RandomNumberGenerator.Fill(nonce);

                    var plaintext = Encoding.UTF8.GetBytes(plaintextJson);
                    var aad = BuildAad(UnmountedVaultEncryption.PublicKeyX25519HkdfXChaCha20Poly1305);
                    var ciphertext = SecretAeadXChaCha20Poly1305.Encrypt(plaintext, nonce, key, aad);

                    var envelope = new UnmountedVaultFile
                    {
                        Algorithm = UnmountedVaultEncryption.PublicKeyX25519HkdfXChaCha20Poly1305,
                        EphemeralPublicKey = ephemeralPublicKey,
                        HkdfSalt = hkdfSalt,
                        Nonce = nonce,
                        Ciphertext = ciphertext,
                    };

                    WriteFile(outputPath, envelope);
                }
                finally { CryptographicOperations.ZeroMemory(key); }
            }
            finally { CryptographicOperations.ZeroMemory(sharedSecret); }
        }

        // ------------------------------------------------------------------ //
        //  Read
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Reads and decrypts a <c>.vault.json.unmounted</c> file using a passphrase.
        /// </summary>
        public static string DecryptWithPassphrase(string inputPath, byte[] passphrase)
        {
            var envelope = ReadFile(inputPath);

            if (envelope.Algorithm != UnmountedVaultEncryption.PassphraseArgon2IdXChaCha20Poly1305)
                throw new InvalidOperationException(
                    $"File was encrypted with {envelope.Algorithm}; use the matching unlock method.");

            if (envelope.Argon2Salt is null)
                throw new InvalidDataException("Missing Argon2id salt in unmounted vault file.");

            var key = PasswordHash.ArgonHashBinary(
                password: passphrase,
                salt: envelope.Argon2Salt,
                opsLimit: 4,
                memLimit: 1 << 28,
                outputLength: 32);

            try
            {
                var aad = BuildAad(envelope.Algorithm);
                var plaintext = SecretAeadXChaCha20Poly1305.Decrypt(envelope.Ciphertext, envelope.Nonce, key, aad);
                return Encoding.UTF8.GetString(plaintext);
            }
            finally { CryptographicOperations.ZeroMemory(key); }
        }

        /// <summary>
        /// Reads and decrypts a <c>.vault.json.unmounted</c> file using the recipient's
        /// raw 32-byte X25519 private key.
        /// </summary>
        public static string DecryptWithPrivateKey(string inputPath, byte[] recipientPrivateKey)
        {
            var envelope = ReadFile(inputPath);

            if (envelope.Algorithm != UnmountedVaultEncryption.PublicKeyX25519HkdfXChaCha20Poly1305)
                throw new InvalidOperationException(
                    $"File was encrypted with {envelope.Algorithm}; use the matching unlock method.");

            if (envelope.EphemeralPublicKey is null || envelope.HkdfSalt is null)
                throw new InvalidDataException("Missing ephemeral public key or HKDF salt in unmounted vault file.");

            var sharedSecret = KeyAgreementManager.GetSharedSecretWithRecipientPrivateKey(
                Enums.KeyWrapping.KeyWrappingAgreementAlgorithm.X25519,
                envelope.EphemeralPublicKey,
                recipientPrivateKey);

            try
            {
                var infoBytes = Encoding.UTF8.GetBytes(HkdfInfo);
                var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32, envelope.HkdfSalt, infoBytes);
                try
                {
                    var aad = BuildAad(envelope.Algorithm);
                    var plaintext = SecretAeadXChaCha20Poly1305.Decrypt(envelope.Ciphertext, envelope.Nonce, key, aad);
                    return Encoding.UTF8.GetString(plaintext);
                }
                finally { CryptographicOperations.ZeroMemory(key); }
            }
            finally { CryptographicOperations.ZeroMemory(sharedSecret); }
        }

        // ------------------------------------------------------------------ //
        //  Binary framing
        // ------------------------------------------------------------------ //

        private static void WriteFile(string outputPath, UnmountedVaultFile envelope)
        {
            using var ms = new MemoryStream();
            using var w = new BinaryWriter(ms);

            // Header
            w.Write(UnmountedVaultFile.Magic);
            w.Write(UnmountedVaultFile.FormatVersion);
            w.Write((byte)envelope.Algorithm);

            if (envelope.Algorithm == UnmountedVaultEncryption.PassphraseArgon2IdXChaCha20Poly1305)
            {
                w.Write(envelope.Argon2Salt!);       // 16 bytes
            }
            else // PublicKey
            {
                w.Write(envelope.EphemeralPublicKey!); // 32 bytes
                w.Write(envelope.HkdfSalt!);            // 16 bytes
            }

            w.Write(envelope.Nonce);                 // 24 bytes
            w.Write((uint)envelope.Ciphertext.Length);
            w.Write(envelope.Ciphertext);

            File.WriteAllBytes(outputPath, ms.ToArray());
        }

        private static UnmountedVaultFile ReadFile(string inputPath)
        {
            if (!File.Exists(inputPath))
                throw new FileNotFoundException($"Unmounted vault file not found: {inputPath}");

            using var ms = new MemoryStream(File.ReadAllBytes(inputPath));
            using var r = new BinaryReader(ms);

            // Validate magic
            var magic = r.ReadBytes(4);
            if (!magic.SequenceEqual(UnmountedVaultFile.Magic))
                throw new InvalidDataException("Not a valid Synccl unmounted vault file.");

            var version = r.ReadByte();
            if (version != UnmountedVaultFile.FormatVersion)
                throw new InvalidDataException($"Unsupported unmounted vault file format version: {version}.");

            var alg = (UnmountedVaultEncryption)r.ReadByte();

            byte[]? argon2Salt = null;
            byte[]? ephemeralPubKey = null;
            byte[]? hkdfSalt = null;

            if (alg == UnmountedVaultEncryption.PassphraseArgon2IdXChaCha20Poly1305)
            {
                argon2Salt = r.ReadBytes(16);
            }
            else if (alg == UnmountedVaultEncryption.PublicKeyX25519HkdfXChaCha20Poly1305)
            {
                ephemeralPubKey = r.ReadBytes(32);
                hkdfSalt = r.ReadBytes(16);
            }
            else
            {
                throw new InvalidDataException($"Unknown encryption algorithm tag: {alg}.");
            }

            var nonce = r.ReadBytes(24);
            var ciphertextLen = r.ReadUInt32();
            var ciphertext = r.ReadBytes((int)ciphertextLen);

            return new UnmountedVaultFile
            {
                Algorithm = alg,
                Argon2Salt = argon2Salt,
                EphemeralPublicKey = ephemeralPubKey,
                HkdfSalt = hkdfSalt,
                Nonce = nonce,
                Ciphertext = ciphertext,
            };
        }

        private static byte[] BuildAad(UnmountedVaultEncryption alg)
            => Encoding.UTF8.GetBytes($"synccl-unmounted-vault|alg={alg}|version=1");
    }
}
