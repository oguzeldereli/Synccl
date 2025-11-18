using Synccl.Core.Diff;
using Synccl.Core.Errors;
using Synccl.Core.Vault;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static Synccl.Core.Diff.SecretDiffEngine;

namespace Synccl.Core.Remote
{
    public interface IRemoteStore
    {
        Task<bool> Exists();
        Task<ServiceResponse> PushAsync(string root, string localNsName, string remoteNsName, ChangeApplicationMode type);
        Task<ServiceResponse> PullAsync(string root, string localNsName, string remoteNsName, ChangeApplicationMode type);
        Task<ServiceResponse<DiffResult>> DiffAsync(string root, string localNsName, string remoteNsName);
        Task<string?> GetHash();
    }
}
