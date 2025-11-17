using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Settings.Namespace
{
    public class NamespaceListCommandSettings : NamespaceCommandSettings
    {
        [CommandOption("-v")]
        public bool ListValues { get; set; } = false;
    }
}
