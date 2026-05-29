namespace Synccl.Core.Model
{
    /// <summary>
    /// Carries the caller-supplied secret material needed to unlock a vault.
    /// For TPM-bound vaults all fields are empty; the TPM itself is the key source.
    /// </summary>
    public sealed class UnlockContext
    {
        public static readonly UnlockContext TpmBound = new();

        /// <summary>UTF-8 passphrase bytes. Zeroed after use by the crypto service.</summary>
        public byte[]? PassphraseBytes { get; init; }

        /// <summary>X25519 private key bytes. Zeroed after use.</summary>
        public byte[]? PrivateKeyBytes { get; init; }

        public bool IsPassphrase => PassphraseBytes is { Length: > 0 };
        public bool IsPublicKey => PrivateKeyBytes is { Length: > 0 };
        public bool IsTpm => !IsPassphrase && !IsPublicKey;

        private UnlockContext() { }

        public static UnlockContext FromPassphrase(byte[] passphraseBytes)
        {
            if (passphraseBytes is null || passphraseBytes.Length == 0)
                throw new ArgumentException("Passphrase bytes cannot be empty.", nameof(passphraseBytes));
            return new UnlockContext { PassphraseBytes = passphraseBytes };
        }

        public static UnlockContext FromPrivateKey(byte[] privateKeyBytes)
        {
            if (privateKeyBytes is null || privateKeyBytes.Length == 0)
                throw new ArgumentException("Private key bytes cannot be empty.", nameof(privateKeyBytes));
            return new UnlockContext { PrivateKeyBytes = privateKeyBytes };
        }
    }
}
