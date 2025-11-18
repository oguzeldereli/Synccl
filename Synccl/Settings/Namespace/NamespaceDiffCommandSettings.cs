using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Settings.Namespace
{
    public class NamespaceDiffCommandSettings : NamespaceCommandSettings
    {
        [CommandArgument(0, "<TARGET_NAMESPACE>")]
        public string TargetNamespace { get; set; } = string.Empty;
    }
}
