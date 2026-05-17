using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Entities.Enums
{
    public enum EncryptedLocalVaultAccessMode
    {
        MountedDeviceBound,
        MountedDeviceBoundPassphraseProtected,
        MountedDeviceBoundPublicKeyProtected,
        UnmountedPassphraseProtected,
        UnmountedPublicKeyProtected
    }
}
