namespace Synccl.Core.Persistence.Dto
{
    public class TpmKeyBlobDto
    {
        public string Ciphertext { get; set; } = string.Empty; // base64
        public string Iv { get; set; } = string.Empty;         // base64
        public string TpmPublicBlob { get; set; } = string.Empty;
        public string TpmPrivateBlob { get; set; } = string.Empty;
        public string Algorithm { get; set; } = string.Empty;
    }
}
