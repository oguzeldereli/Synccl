namespace Synccl.Core.Model
{
    /// <summary>Light-weight metadata about a vault, safe to surface without decryption.</summary>
    public sealed class VaultInfo
    {
        public Guid Id { get; init; }
        public string Name { get; init; } = string.Empty;
        public string FilePath { get; init; } = string.Empty;
        public int Version { get; init; }
        public string AccessMode { get; init; } = string.Empty;
        public string DefaultNamespaceName { get; init; } = string.Empty;
        public IReadOnlyList<string> NamespaceNames { get; init; } = [];
    }
}
