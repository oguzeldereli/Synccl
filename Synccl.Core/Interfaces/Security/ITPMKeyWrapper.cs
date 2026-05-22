using Synccl.Core.Model.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Interfaces.Security
{
    public interface ITPMKeyWrapper
    {
        TPMKeyBlob Wrap(byte[] keyMaterial);

        byte[] Unwrap(TPMKeyBlob wrappedKey);
    }
}
