using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Settings.Remote
{
    public class RemoteRemoveCommandSettings : CommandSettings
    {
        [CommandArgument(0, "[NAME]")]
        public string Name { get; set; } = "origin";

        [CommandOption("--force")]
        public bool Force { get; set; } = false;
    }
}
