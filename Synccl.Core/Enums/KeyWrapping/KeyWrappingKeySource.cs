using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Enums.KeyWrapping
{
    public enum KeyWrappingKeySource
    {
        TPMBlob,
        Passphrase,
        PublicKey,
        ParentKey,
    }
}
