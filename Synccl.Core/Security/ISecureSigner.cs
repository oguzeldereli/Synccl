using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Security
{
    public interface ISecureSigner
    {
        byte[] GetDevicePublicKey();
        byte[] SignData(byte[] data);
        bool VerifyP256(byte[] data, byte[] signature, byte[] publicKey);
        void DeleteStorageParent();
        void DeleteSigningKey();
    }
}
