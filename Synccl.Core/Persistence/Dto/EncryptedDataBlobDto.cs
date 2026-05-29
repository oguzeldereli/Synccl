namespace Synccl.Core.Persistence.Dto
{
    public class EncryptedDataBlobDto
    {
        public string Algorithm { get; set; } = string.Empty;
        public string Ciphertext { get; set; } = string.Empty; // base64
        public string Nonce { get; set; } = string.Empty;
        public string Aad { get; set; } = string.Empty;
        public Guid EncryptedBy { get; set; }
    }
}
