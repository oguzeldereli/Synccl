using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Config
{
    public class SyncclConfig
    {
        public List<RemoteConfig> Remotes { get; set; } = new();
    }
}
