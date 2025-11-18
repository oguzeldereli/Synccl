using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Keys
{
    public interface IKeychain
    {
        bool TryGetKey(string account, out byte[] key);
        bool TrySetKey(string account, byte[] key);
        bool TryDeleteKey(string account);
    }
}
