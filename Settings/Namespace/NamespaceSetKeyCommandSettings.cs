using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Settings.Namespace
{
    public class NamespaceSetCommandSettings : NamespaceCommandSettings
    {
        [CommandArgument(0, "<KEY>")]
        public string Key { get; set; } = string.Empty;
        [CommandArgument(1, "<VALUE>")]
        public string Value { get; set; } = string.Empty;
    }
}
