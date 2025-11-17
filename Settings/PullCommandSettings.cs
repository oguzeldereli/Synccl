using Spectre.Console;
using Spectre.Console.Cli;
using Synccl.Cli.Composition;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Settings
{
    public class PullCommandSettings : CommandSettings
    {
        [CommandArgument(0, "[ARG1]")]
        [Description("Namespace or RemoteName, depending on how many arguments are provided.")]
        public string? Arg1 { get; set; }

        [CommandArgument(1, "[ARG2]")]
        [Description("RemoteName or RemoteNamespace, depending on how many arguments are provided.")]
        public string? Arg2 { get; set; }

        [CommandArgument(2, "[ARG3]")]
        [Description("RemoteNamespace if three arguments are provided.")]
        public string? Arg3 { get; set; }

        [CommandOption("--hard")]
        public bool Hard { get; set; }

        [CommandOption("--merge")]
        public bool Merge { get; set; }

        public string? Namespace { get; set; } = null;
        public string RemoteName { get; set; } = "origin";
        public string? RemoteNamespace { get; set; } = null;

        public override ValidationResult Validate()
        {
            if (Hard && Merge)
            {
                return ValidationResult.Error("Cannot use --hard and --merge options together.");
            }

            var providedArgs = new[] { Arg1, Arg2, Arg3 }.Where(a => a != null).ToList();

            switch (providedArgs.Count)
            {
                case 0:
                    RemoteName = "origin";
                    Namespace = RemoteNamespace = null;
                    break;
                case 1:
                    RemoteName = providedArgs[0]!;
                    Namespace = RemoteNamespace = null;
                    break;
                case 2:
                    var remote = ServiceFactory.CreateRemote(Environment.CurrentDirectory, providedArgs[0]!);
                    if (remote != null)
                    {
                        RemoteName = providedArgs[0] ?? "origin";
                        Namespace = RemoteNamespace = providedArgs[1];
                    }
                    else
                    {
                        RemoteNamespace = Namespace = providedArgs[0];
                        RemoteName = providedArgs[1] ?? "origin";
                    }
                    break;
                case 3:
                    Namespace = providedArgs[0];
                    RemoteName = providedArgs[1] ?? "origin";
                    RemoteNamespace = providedArgs[2];
                    break;
                default:
                    return ValidationResult.Error("Too many arguments provided.");
            }

            return base.Validate();
        }
    }
}