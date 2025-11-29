using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Keys
{
    public interface ISecureKeyWrapper
    {
        public (byte[] privBlob, byte[] pubBlob) RequireRSAKeyBlobs();
        byte[] WrapKeyWithTPM(byte[] key, byte[] privBlob, byte[] pubBlob);
        byte[] UnwrapKeyWithTPM(byte[] wrappedKey, byte[] privBlob, byte[] pubBlob);
        byte[] GetPublicKey(byte[] privBlob, byte[] pubBlob);
    }
}
    