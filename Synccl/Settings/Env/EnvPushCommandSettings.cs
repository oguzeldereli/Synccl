using Spectre.Console;
using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Settings.Env
{
    public class EnvPushCommandSettings : CommandSettings
    {
        [CommandArgument(1, "[PATH]")]
        public string Path { get; set; } = System.IO.Path.Combine(Environment.CurrentDirectory, ".env");

        [CommandOption("-n|--namespace <NAMESPACE>")]
        public string? Namespace { get; set; } = null;

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
