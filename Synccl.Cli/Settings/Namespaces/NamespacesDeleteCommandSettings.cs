using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Settings.Namespaces
{
    public class NamespacesDeleteCommandSettings : CommandSettings
    {
        [CommandArgument(0, "<NAMESPACE>")]
        public string Namespace { get; set; } = string.Empty;

        [CommandOption("--force")]
        public bool Force { get; set; }
    }
}
