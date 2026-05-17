using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Entities.Enums.KeyWrapping
{
    public enum KeyWrappingSource
    {
        TPM,
        Passphrase,
        PublicKey,
        ParentKey,
    }
}
