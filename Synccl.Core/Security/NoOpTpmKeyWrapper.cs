using Synccl.Core.Interfaces.Security;
using Synccl.Core.Model.Security;
using System.Security.Cryptography;

namespace Synccl.Core.Security
{
    /// <summary>
    /// Fallback TPM key wrapper that uses platform-backed data protection (DPAPI on Windows,
    /// or AES-256-GCM with a machine-scoped key on other platforms) when a real TPM is unavailable.
    /// </summary>
    public sealed class NoOpTpmKeyWrapper : ITPMKeyWrapper
    {
        // Machine-scoped entropy used to differentiate this app's keys from others.
        private static readonly byte[] AppEntropy = "synccl-tpm-stub-v1"u8.ToArray();

        public TPMKeyBlob Wrap(byte[] keyMaterial)
        {
            var ciphertext = ProtectBytes(keyMaterial);
            return TPMKeyBlob.Create(
                ciphertext,
                iv: [],
                tpmPublicBlob: [],
                tpmPrivateBlob: [],
                Enums.KeyWrapping.KeyWrappingEncryptionAlgorithm.AES_256);
        }

        public byte[] Unwrap(TPMKeyBlob wrappedKey)
            => UnprotectBytes(wrappedKey.Ciphertext);

        private static byte[] ProtectBytes(byte[] data)
        {
            if (OperatingSystem.IsWindows())
            {
                return System.Security.Cryptography.ProtectedData.Protect(
                    data, AppEntropy, System.Security.Cryptography.DataProtectionScope.LocalMachine);
            }

            // Non-Windows: AES-256-GCM with a machine-derived key.
            var key = DeriveLocalMachineKey();
            var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
            RandomNumberGenerator.Fill(nonce);
            var ciphertext = new byte[data.Length];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize];

            using var aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
            aes.Encrypt(nonce, data, ciphertext, tag);

            // Layout: [nonce (12)] [tag (16)] [ciphertext]
            var result = new byte[nonce.Length + tag.Length + ciphertext.Length];
            nonce.CopyTo(result, 0);
            tag.CopyTo(result, nonce.Length);
            ciphertext.CopyTo(result, nonce.Length + tag.Length);
            return result;
        }

        private static byte[] UnprotectBytes(byte[] blob)
        {
            if (OperatingSystem.IsWindows())
            {
                return System.Security.Cryptography.ProtectedData.Unprotect(
                    blob, AppEntropy, System.Security.Cryptography.DataProtectionScope.LocalMachine);
            }

            var key = DeriveLocalMachineKey();
            const int nonceLen = 12, tagLen = 16;
            var nonce = blob[..nonceLen];
            var tag = blob[nonceLen..(nonceLen + tagLen)];
            var ciphertext = blob[(nonceLen + tagLen)..];
            var plaintext = new byte[ciphertext.Length];

            using var aes = new AesGcm(key, tagLen);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
            return plaintext;
        }

        private static byte[] DeriveLocalMachineKey()
        {
            // Machine-unique but stable material: machine name + app entropy.
            var machineId = System.Text.Encoding.UTF8.GetBytes(
                Environment.MachineName + "|synccl");
            return SHA256.HashData(machineId);
        }
    }
}
