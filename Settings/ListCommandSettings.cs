using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Settings
{
    public class ListCommandSettings : CommandSettings
    {
        [CommandOption("-v")]
        public bool ListValues { get; set; } = false;

        [CommandOption("-n|--namespace <NAMESPACE>")]
        public string? Namespace { get; set; } = null;
    }
}
