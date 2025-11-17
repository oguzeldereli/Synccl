using Spectre.Console;
using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Settings.Namespace
{
    public class NamespacePullCommandSettings : NamespaceCommandSettings
    {
        [CommandArgument(0, "[SOURCE_NAMESPACE]")]
        public string? SourceNamespace { get; set; }

        [CommandOption("--hard")]
        public bool Hard { get; set; }

        [CommandOption("--merge")]
        public bool Merge { get; set; }

        public override ValidationResult Validate()
        {
            if (Hard && Merge)
            {
                return ValidationResult.Error("The --merge and --hard options are mutually exclusive. Please specify only one.");
            }
            return base.Validate();
        }
    }
}
