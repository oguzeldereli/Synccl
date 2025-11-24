using Sodium;
using Synccl.Core.Crypto;
using Synccl.Core.Vault;
using System;
using static Synccl.Core.Vault.KeyWrap;

namespace Synccl.Core.VaultCrypto
{
    public sealed class VaultCryptoEngine
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

        public EncryptedBlob EncryptValue(byte[] plaintext, byte[] itemKey)
        {
            var nonce = SodiumCore.GetRandomBytes(24);
            var aad = System.Text.Encoding.UTF8.GetBytes("synccl-secret-v1");

            var ct = SecretAeadXChaCha20Poly1305.Encrypt(
                plaintext,
                nonce,
                itemKey,
                aad
            );

            return new EncryptedBlob
            {
                Algorithm = "xchacha20poly1305",
                Nonce = nonce,
                Ciphertext = ct,
                Aad = "synccl-secret-v1"
            };
        }

        public byte[] DecryptValue(EncryptedBlob blob, byte[] itemKey)
        {
            var aad = blob.Aad != null
                ? System.Text.Encoding.UTF8.GetBytes(blob.Aad)
                : Array.Empty<byte>();

            return SecretAeadXChaCha20Poly1305.Decrypt(
                blob.Ciphertext,
                blob.Nonce,
                itemKey,
                aad
            );
        }
    }
}
