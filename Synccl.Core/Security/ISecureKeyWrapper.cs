using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Keys
{
    public interface ISecureKeyWrapper
    {
        (byte[] privBlob, byte[] pubBlob) WrapKeyWithTPM(byte[] key);
        byte[] UnwrapKeyWithTPM(byte[] privBlob, byte[] pubBlob);
        void DeleteStorageParent();
    }
}
    