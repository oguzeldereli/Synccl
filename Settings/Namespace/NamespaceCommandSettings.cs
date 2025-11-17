using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Settings.Namespace
{
    public class NamespaceCommandSettings : CommandSettings
    {
        [CommandArgument(0, "[NAMESPACE]")]
        public string? Namespace { get; set; }
    }
}
