using Synccl.Core.Enums.KeyWrapping;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Model.Security
{
    public class KeyWrappingEncryptionBlob
    {
        public KeyWrappingKeySource Source { get; set; }
        public KeyWrappingEncryptionAlgorithm Algorithm { get; private set; }
        public TPMKeyBlob? TPMWrapKeyResult { get; private set; }
        public byte[]? Ciphertext { get; private set; }
        public byte[]? Nonce { get; private set; }
        public byte[]? Aad { get; private set; }

        private KeyWrappingEncryptionBlob(
            KeyWrappingKeySource source, 
            KeyWrappingEncryptionAlgorithm algorithm, 
            TPMKeyBlob? tpmWrapKeyResult, 
            byte[]? ciphertext, 
            byte[]? nonce, 
            byte[]? aad)
        {
            Source = source;
            Algorithm = algorithm;
            TPMWrapKeyResult = tpmWrapKeyResult;
            Ciphertext = ciphertext;
            Nonce = nonce;
            Aad = aad;
        }

        public static KeyWrappingEncryptionBlob CreateForTPM(TPMKeyBlob tpmWrapKeyResult)
        {
            if (tpmWrapKeyResult == null)
                throw new ArgumentNullException(nameof(tpmWrapKeyResult));
            return new KeyWrappingEncryptionBlob(
                KeyWrappingKeySource.TPMBlob,
                tpmWrapKeyResult.Algorithm,
                tpmWrapKeyResult,
                tpmWrapKeyResult.Ciphertext, null, null);
        }

        public static KeyWrappingEncryptionBlob CreateForSymmetric(
            KeyWrappingKeySource source, 
            KeyWrappingEncryptionAlgorithm algorithm, 
            byte[] ciphertext, 
            byte[] nonce, 
            byte[] aad)
        {
            if (ciphertext == null || ciphertext.Length == 0)
                throw new ArgumentException("Ciphertext cannot be null or empty.", nameof(ciphertext));
            if (nonce == null || nonce.Length == 0)
                throw new ArgumentException("Nonce cannot be null or empty.", nameof(nonce));
            if (aad == null || aad.Length == 0)
                throw new ArgumentException("AAD cannot be null or empty.", nameof(aad));
            return new KeyWrappingEncryptionBlob(
                source,
                algorithm,
                null,
                ciphertext, nonce, aad);
        }
    }
}
