using System.Collections.Generic;
using System.Linq;

namespace Synccl.Core.Diff;

public static class SecretDiffEngine
{
    public enum ChangeApplicationMode
    {
        Add,
        AddOrUpdate,
        AddOrUpdateOrDelete,
    }

    public static DiffResult Compare(
        IDictionary<string, string> src,
        IDictionary<string, string> target)
    {
        var changes = new List<SecretChange>();

        foreach (var key in src.Keys)
        {
            if (!target.ContainsKey(key))
            {
                changes.Add(new SecretChange(key, SecretChangeType.Add, null, src[key]));
            }
            else if (src[key] != target[key])
            {
                changes.Add(new SecretChange(key, SecretChangeType.Update, target[key], src[key]));
            }
            else
            {
                changes.Add(new SecretChange(key, SecretChangeType.NoChange, src[key], target[key]));
            }
        }

        foreach (var key in target.Keys.Where(k => !src.ContainsKey(k)))
        {
            changes.Add(new SecretChange(key, SecretChangeType.Delete, target[key], null));
        }

        return new DiffResult(changes);
    }

    public static IDictionary<string, string> ApplyDiff(
        DiffResult diff,
        IDictionary<string, string> src,
        IDictionary<string, string> target,
        ChangeApplicationMode mode)
    {
        var result = new Dictionary<string, string>(target);

        foreach (var change in diff.Changes)
        {
            switch (change.Type)
            {
                case SecretChangeType.Add:
                    if (mode is ChangeApplicationMode.Add
                        or ChangeApplicationMode.AddOrUpdate
                        or ChangeApplicationMode.AddOrUpdateOrDelete)
                    {
                        result[change.Key] = src[change.Key];
                    }
                    break;

                case SecretChangeType.Update:
                    if (mode is ChangeApplicationMode.AddOrUpdate
                        or ChangeApplicationMode.AddOrUpdateOrDelete)
                    {
                        result[change.Key] = src[change.Key];
                    }
                    break;

                case SecretChangeType.Delete:
                    if (mode is ChangeApplicationMode.AddOrUpdateOrDelete)
                    {
                        result.Remove(change.Key);
                    }
                    break;
            }
        }
        return result;
    }
}

