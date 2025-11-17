using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Config
{
    public class RemoteConfig
    {
        public string Name { get; set; } = "";
        public string Type { get; set; } = "";
        public string Bucket { get; set; } = "";
        public string Prefix { get; set; } = "";
        public string Region { get; set; } = "";
        public string? Profile { get; set; }
    }
}
