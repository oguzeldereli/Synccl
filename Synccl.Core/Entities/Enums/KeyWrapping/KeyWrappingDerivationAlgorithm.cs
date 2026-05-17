using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Entities.Enums.KeyWrapping
{
    public enum KeyWrappingDerivationAlgorithm
    {
        None = 0,
        HKDF_SHA256 = 1,
        Argon2Id = 2,
    }
}
