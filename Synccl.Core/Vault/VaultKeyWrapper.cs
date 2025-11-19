using Sodium;
using Synccl.Core.Crypto;
using Synccl.Core.Device;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using static Synccl.Core.Vault.KeyWrap;

namespace Synccl.Core.Vault
{
    public class VaultKeyWrapper
    {
        public static KeyWrap WrapForDevice(Guid deviceId, byte[] devicePubKey, byte[] key, KeyType type, Guid keyId, int version)
        {
            byte[] wrapped = Envelope.WrapDekWithX25519(key, devicePubKey);

            return new KeyWrap
            {
                DeviceId = deviceId,
                DevicePublicKeyForWrap = devicePubKey,
                KeyId = keyId,
                KeyVersion = version,
                Type = type,
                WrappedKey = wrapped,
                WrapAlgorithm = "x25519-xchacha20"
            };
        }

        public static KeyWrap EncryptAndWrapForDevice(Guid deviceId, byte[] devicePubKey, byte[] encryptionKey, byte[] key, byte[] aad, KeyType type, Guid keyId, int version)
        {
            var nonce = SodiumCore.GetRandomBytes(24);
            var encNK = SecretAeadXChaCha20Poly1305.Encrypt(key, nonce, encryptionKey, aad);

            var combined = new byte[nonce.Length + encNK.Length];
            Buffer.BlockCopy(nonce, 0, combined, 0, nonce.Length);
            Buffer.BlockCopy(encNK, 0, combined, nonce.Length, encNK.Length);

            var wrapped = Envelope.WrapDekWithX25519(combined, devicePubKey);

            return new KeyWrap
            {
                DeviceId = deviceId,
                DevicePublicKeyForWrap = devicePubKey,
                KeyId = keyId,
                KeyVersion = version,
                Type = type,
                WrappedKey = wrapped,
                WrapAlgorithm = "x25519+vk"
            };
        }
    }
}
