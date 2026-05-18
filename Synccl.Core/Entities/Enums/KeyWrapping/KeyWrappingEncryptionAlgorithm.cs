using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Entities.Enums.KeyWrapping
{
    public enum KeyWrappingEncryptionAlgorithm
    {
        AES_128,
        AES_256,
        RSA_OAEP,
        XChaCha20Poly1305
    }
}
