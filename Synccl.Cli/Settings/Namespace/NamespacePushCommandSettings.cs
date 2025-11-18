using Spectre.Console;
using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Settings.Namespace
{
    public class NamespacePushCommandSettings : NamespaceCommandSettings
    {
        [CommandArgument(0, "[TARGET_NAMESPACE]")]
        public string? TargetNamespace { get; set; }

        [CommandOption("--prune")]
        public bool Prune { get; set; } = false;

        [CommandOption("--strict")]
        public bool Strict { get; set; } = false;

        public override ValidationResult Validate()
        {
            if (Prune && Strict)
            {
                return ValidationResult.Error("The --prune and --strict options cannot be used together.");
            }

            return base.Validate();
        }
    }
}
