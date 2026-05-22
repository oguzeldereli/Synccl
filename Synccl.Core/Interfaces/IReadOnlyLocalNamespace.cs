using Synccl.Core.Model.LocalVault;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Interfaces
{
    public interface IReadOnlyLocalNamespace
    {
        Guid Id { get; }
        string Name { get; }
        string this[string key] { get; }
        IReadOnlyDictionary<string, LocalItem> GetItems();
        bool TryGet(string key, out string? value);
        bool ContainsKey(string key);
    }
}
