using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Env
{
    public abstract record EnvLine;

    public record EnvKeyValue(string Key, string Value, string Raw, string? Comment) : EnvLine;

    public record EnvComment(string Text) : EnvLine;

    public record EnvBlank() : EnvLine;
}
