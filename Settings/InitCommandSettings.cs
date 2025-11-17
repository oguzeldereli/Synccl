using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Settings
{
    public sealed class InitCommandSettings : CommandSettings
    {
        [CommandArgument(0, "[PATH]")]
        public string Path { get; set; } = Environment.CurrentDirectory;
    }
}
