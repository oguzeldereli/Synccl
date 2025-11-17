using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Settings.Env
{
    public class EnvDiffCommandSettings : CommandSettings
    {
        [CommandOption("-n|--namespace <NAMESPACE>")]
        public string? Namespace { get; set; } = null;

        [CommandArgument(0, "[PATH]")]
        public string Path { get; set; } = System.IO.Path.Combine(Environment.CurrentDirectory, ".env");
    }
}
