using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Enums.KeyWrapping
{
    public enum KeyWrappingProfile
    {
        TpmAes128,
        TpmAes256,
        PassphraseArgon2IdXChaCha20Poly1305,
        PublicKeyX25519HkdfXChaCha20Poly1305,
        ParentKeyXChaCha20Poly1305
    }
}
