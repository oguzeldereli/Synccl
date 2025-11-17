using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Settings
{
    public class UnsetCommandSettings : CommandSettings
    {
        [CommandArgument(0, "<KEY>")]
        public string Key { get; set; } = string.Empty;

        [CommandOption("-n|--namespace <NAMESPACE>")]
        public string? Namespace { get; set; } = null;
    }
}
