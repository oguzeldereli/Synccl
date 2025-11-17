using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Settings.Remote.Add
{
    public class RemoteAddCommandSettings : CommandSettings
    {
        [CommandArgument(0, "[NAME]")]
        public string Name { get; set; } = "origin";
    }
}
