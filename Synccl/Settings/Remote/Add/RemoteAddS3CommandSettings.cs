using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Settings.Remote.Add
{
    public class RemoteAddS3CommandSettings : RemoteAddCommandSettings
    {
        [CommandOption("--bucket <BUCKET>")]
        public string? Bucket { get; set; } = default!;
        [CommandOption("--region <REGION>")]
        public string? Region { get; set; } = default!;
        [CommandOption("--prefix <PREFIX>")]
        public string? Prefix { get; set; } = default!;
        [CommandOption("--profile <PROFILE>")]
        public string? Profile { get; set; } = default!;
    }
}
