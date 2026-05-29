namespace Synccl.Core.Persistence.Dto
{
    public class KeyWrapDto
    {
        public Guid Id { get; set; }
        public Guid WrappedKeyId { get; set; }
        public Guid? WrappingKeyId { get; set; }
        public string Profile { get; set; } = string.Empty;
        public DateTime CreatedAtUtc { get; set; }
        public string WrappedKey { get; set; } = string.Empty; // base64

        // Symmetric
        public string? Nonce { get; set; }
        public string? Aad { get; set; }

        // TPM
        public string? TpmEndorsementKeyHash { get; set; }
        public TpmKeyBlobDto? TpmKeyBlob { get; set; }

        // KDF
        public string? Salt { get; set; }
        public string? Info { get; set; }

        // Public key agreement
        public string? EphemeralPublicKey { get; set; }

        // Argon2
        public int? Argon2MemoryKiB { get; set; }
        public int? Argon2Iterations { get; set; }
    }
}
