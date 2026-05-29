namespace Synccl.Core.Persistence.Dto
{
    public class EncryptedLocalItemDto
    {
        public Guid Id { get; set; }
        public string Key { get; set; } = string.Empty;
        public EncryptedDataBlobDto Payload { get; set; } = null!;
        public List<KeyWrapDto> WrappedItemKeys { get; set; } = [];
    }
}
