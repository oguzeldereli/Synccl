namespace Synccl.Core.Persistence.Dto
{
    public class EncryptedLocalVaultDto
    {
        public int SchemaVersion { get; set; } = 1;
        public Guid Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public int Version { get; set; }
        public string DefaultNamespaceName { get; set; } = "default";
        public string AccessMode { get; set; } = string.Empty;
        public List<KeyWrapDto> WrappedVaultKeys { get; set; } = [];
        public List<EncryptedLocalNamespaceDto> Namespaces { get; set; } = [];
    }
}
