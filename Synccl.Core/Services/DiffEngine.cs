using Synccl.Core.Model;
using Synccl.Core.Model.LocalVault;

namespace Synccl.Core.Services
{
    /// <summary>
    /// Computes the diff between two decrypted namespaces.
    /// </summary>
    public static class DiffEngine
    {
        public static DiffResult Compute(
            LocalNamespaceSnapshot source,
            LocalNamespaceSnapshot destination)
        {
            var srcItems = source.GetItems();
            var dstItems = destination.GetItems();

            var allKeys = srcItems.Keys.Union(dstItems.Keys).OrderBy(k => k);

            var entries = new List<DiffEntry>();
            foreach (var key in allKeys)
            {
                var inSrc = srcItems.TryGetValue(key, out var srcItem);
                var inDst = dstItems.TryGetValue(key, out var dstItem);

                if (inSrc && !inDst)
                    entries.Add(new DiffEntry { Key = key, Kind = DiffEntryKind.Added, SourceValue = srcItem!.Value });
                else if (!inSrc && inDst)
                    entries.Add(new DiffEntry { Key = key, Kind = DiffEntryKind.Removed, DestinationValue = dstItem!.Value });
                else if (srcItem!.Value != dstItem!.Value)
                    entries.Add(new DiffEntry { Key = key, Kind = DiffEntryKind.Modified, SourceValue = srcItem.Value, DestinationValue = dstItem.Value });
                else
                    entries.Add(new DiffEntry { Key = key, Kind = DiffEntryKind.Unchanged });
            }

            return new DiffResult { Entries = entries };
        }
    }
}
