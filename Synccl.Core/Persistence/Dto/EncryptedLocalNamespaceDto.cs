namespace Synccl.Core.Persistence.Dto
{
    public class EncryptedLocalNamespaceDto
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public List<KeyWrapDto> WrappedNamespaceKeys { get; set; } = [];
        public List<EncryptedLocalItemDto> Items { get; set; } = [];
    }
}
