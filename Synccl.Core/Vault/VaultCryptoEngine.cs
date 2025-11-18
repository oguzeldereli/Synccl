using System;
using Sodium;
using Synccl.Core.Vault;

namespace Synccl.Core.VaultCrypto
{
    public sealed class VaultCryptoEngine
    {
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

        public EncryptedBlob EncryptKeyWithNamespaceKey(byte[] rawKey, byte[] namespaceKey)
        {
            var nonce = Sodium.SodiumCore.GetRandomBytes(24);
            var aad = System.Text.Encoding.ASCII.GetBytes("synccl/ik-wrap/v1");

            var ct = Sodium.SecretAeadXChaCha20Poly1305.Encrypt(
                rawKey, 
                nonce, 
                namespaceKey, 
                aad);

            return new EncryptedBlob 
            { 
                Algorithm = "xchacha20poly1305", 
                Nonce = nonce, 
                Ciphertext = ct, 
                Aad = "synccl/ik-wrap/v1" 
            };
        }

        public byte[] DecryptKeyWithNamespaceKey(EncryptedBlob blob, byte[] namespaceKey)
        {
            var aad = blob.Aad != null 
                ? System.Text.Encoding.ASCII.GetBytes(blob.Aad) 
                : Array.Empty<byte>();

            return Sodium.SecretAeadXChaCha20Poly1305.Decrypt(
                blob.Ciphertext, 
                blob.Nonce, 
                namespaceKey, 
                aad);
        }

    }
}
