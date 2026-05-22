using Sodium;
using Synccl.Core.Enums.KeyWrapping;
using Synccl.Core.Interfaces.Security;
using Synccl.Core.Model.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Security
{
    public class KeyEncryptionManager
    {
        private readonly ITPMKeyWrapper _tpmKeyWrapper;

        public KeyEncryptionManager(
            ITPMKeyWrapper tpmKeyWrapper)
        {
            _tpmKeyWrapper = tpmKeyWrapper;
        }

        public KeyWrappingEncryptionBlob Encrypt(
            KeyWrappingKeySource encryptionSource,
            KeyWrappingEncryptionAlgorithm algorithm,
            byte[] keyToEncrypt,
            byte[]? encryptionKey,
            byte[]? additionalData)
        {
            if (encryptionSource == KeyWrappingKeySource.TPMBlob)
            {
                var tpmKeyBlob = _tpmKeyWrapper.Wrap(keyToEncrypt);
                return KeyWrappingEncryptionBlob.CreateForTPM(tpmKeyBlob);
            }
            else if (encryptionKey == null || encryptionKey.Length == 0)
            {
                throw new ArgumentException("A valid encryption key must be provided for non-TPM encryption sources.");
            }

            switch (algorithm)
            {
                case KeyWrappingEncryptionAlgorithm.AES_128:
                    if (encryptionKey.Length != 16)
                    {
                        throw new ArgumentException("Encryption key must be 16 bytes long for AES-128.");
                    }

                    var nonce = new byte[12];
                    RandomNumberGenerator.Fill(nonce);
                    var result = SecretAeadAes.Encrypt(keyToEncrypt, nonce, encryptionKey, additionalData);
                    return KeyWrappingEncryptionBlob.CreateForSymmetric(
                        encryptionSource,
                        algorithm,
                        result,
                        nonce,
                        additionalData ?? Array.Empty<byte>());

                case KeyWrappingEncryptionAlgorithm.AES_256:
                    if (encryptionKey.Length != 32)
                    {
                        throw new ArgumentException("Encryption key must be 32 bytes long for AES-256.");
                    }

                    nonce = new byte[12];
                    RandomNumberGenerator.Fill(nonce);
                    result = SecretAeadAes.Encrypt(keyToEncrypt, nonce, encryptionKey, additionalData);
                    return KeyWrappingEncryptionBlob.CreateForSymmetric(
                        encryptionSource,
                        algorithm,
                        result,
                        nonce,
                        additionalData ?? Array.Empty<byte>());

                case KeyWrappingEncryptionAlgorithm.XChaCha20Poly1305:
                    if (encryptionKey.Length != 32)
                    {
                        throw new ArgumentException("Encryption key must be 32 bytes long for XChaCha20Poly1305.");
                    }

                    nonce = new byte[24];
                    RandomNumberGenerator.Fill(nonce);
                    result = SecretAeadXChaCha20Poly1305.Encrypt(keyToEncrypt, nonce, encryptionKey, additionalData);
                    return KeyWrappingEncryptionBlob.CreateForSymmetric(
                        encryptionSource,
                        algorithm,
                        result,
                        nonce,
                        additionalData ?? Array.Empty<byte>());

                default:
                    throw new NotSupportedException($"The encryption algorithm {algorithm} is not supported.");
            }
        }

        public byte[] Decrypt(
            KeyWrappingKeySource source,
            KeyWrappingEncryptionAlgorithm algorithm,
            byte[]? ciphertext,
            byte[]? decryptionKey,
            byte[]? nonce,
            byte[]? aad,
            TPMKeyBlob? tpmKeyBlob)
        {
            if (source == KeyWrappingKeySource.TPMBlob)
            {
                if (tpmKeyBlob == null)
                {
                    throw new ArgumentException("The encrypted blob does not contain a valid TPM wrap key result.");
                }

                var result = _tpmKeyWrapper.Unwrap(tpmKeyBlob);
                return result;
            }
            else if (decryptionKey == null || decryptionKey.Length == 0)
            {
                throw new ArgumentException("A valid decryption key must be provided for non-TPM encrypted blobs.");
            }
            else if (ciphertext == null || ciphertext.Length == 0)
            {
                throw new ArgumentException("The encrypted blob does not contain valid ciphertext.");
            }
            else if (nonce == null || nonce.Length == 0)
            {
                throw new ArgumentException("The encrypted blob does not contain a valid nonce.");
            }
            else if (aad == null || aad.Length == 0)
            {
                throw new ArgumentException("The encrypted blob does not contain valid additional data.");
            }

            switch (algorithm)
            {
                case KeyWrappingEncryptionAlgorithm.AES_128:
                    if (decryptionKey?.Length != 16)
                    {
                        throw new ArgumentException("Decryption key must be 16 bytes long for AES-128.");
                    }

                    return SecretAeadAes.Decrypt(
                        ciphertext ?? throw new InvalidOperationException("Ciphertext is required for AES-128 decryption."), 
                        nonce ?? throw new InvalidOperationException("Nonce is required for AES-128 decryption."), 
                        decryptionKey, 
                        aad ?? throw new InvalidOperationException("AAD is required for AES-128 decryption."));  
                case KeyWrappingEncryptionAlgorithm.AES_256:
                    if (decryptionKey?.Length != 32)
                    {
                        throw new ArgumentException("Decryption key must be 32 bytes long for AES-256.");
                    }

                    return SecretAeadAes.Decrypt(
                        ciphertext ?? throw new InvalidOperationException("Ciphertext is required for AES-256 decryption."),
                        nonce ?? throw new InvalidOperationException("Nonce is required for AES-256 decryption."),
                        decryptionKey,
                        aad ?? throw new InvalidOperationException("AAD is required for AES-256 decryption."));
                case KeyWrappingEncryptionAlgorithm.XChaCha20Poly1305:
                    if (decryptionKey?.Length != 32)
                    {
                        throw new ArgumentException("Decryption key must be 32 bytes long for XChaCha20Poly1305.");
                    }

                    return SecretAeadXChaCha20Poly1305.Decrypt(
                        ciphertext ?? throw new InvalidOperationException("Ciphertext is required for XChaCha20Poly1305 decryption."),
                        nonce ?? throw new InvalidOperationException("Nonce is required for XChaCha20Poly1305 decryption."),
                        decryptionKey,
                        aad ?? throw new InvalidOperationException("AAD is required for XChaCha20Poly1305 decryption."));
                default:
                    throw new NotSupportedException($"The encryption algorithm {algorithm} is not supported.");
            }
        }
    }
}
