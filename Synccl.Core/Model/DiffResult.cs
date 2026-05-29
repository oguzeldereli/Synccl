namespace Synccl.Core.Model
{
    public enum DiffEntryKind { Added, Removed, Modified, Unchanged }

    public sealed class DiffEntry
    {
        public string Key { get; init; } = string.Empty;
        public DiffEntryKind Kind { get; init; }
        public string? SourceValue { get; init; }
        public string? DestinationValue { get; init; }
    }

    public sealed class DiffResult
    {
        public IReadOnlyList<DiffEntry> Entries { get; init; } = [];

        public bool HasChanges => Entries.Any(e => e.Kind != DiffEntryKind.Unchanged);

        public IEnumerable<DiffEntry> Added => Entries.Where(e => e.Kind == DiffEntryKind.Added);
        public IEnumerable<DiffEntry> Removed => Entries.Where(e => e.Kind == DiffEntryKind.Removed);
        public IEnumerable<DiffEntry> Modified => Entries.Where(e => e.Kind == DiffEntryKind.Modified);
    }
}
