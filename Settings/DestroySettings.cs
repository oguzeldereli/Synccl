using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Settings
{
    public class DestroySettings : CommandSettings
    {
        [CommandArgument(0, "[PATH]")]
        public string Path { get; set; } = Environment.CurrentDirectory;

        [CommandOption("--force")]
        public bool Force { get; set; }

        [CommandOption("--delete-config")]
        public bool DeleteConfig { get; set; } = false;
    }
}
