using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Diff
{
    public record SecretChange(
        string Key,
        SecretChangeType Type,
        string? OldValue,
        string? NewValue
    );
}
