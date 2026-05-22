using Synccl.Core.Enums.KeyWrapping;
using Synccl.Core.Interfaces.Security;
using Synccl.Core.Model.Security;
using System;
using System.Security.Cryptography;
using System.Text;

namespace Synccl.Core.Security
{
    public class KeyWrapper
    {
        private readonly ITPMKeyWrapper _tpmKeyWrapper;
        private readonly ITPMManager _tpmManager;
        private readonly KeyEncryptionManager _encryptionManager;

        public KeyWrapper(ITPMKeyWrapper tpmKeyWrapper, ITPMManager tpmManager)
        {
            _tpmKeyWrapper = tpmKeyWrapper ?? throw new ArgumentNullException(nameof(tpmKeyWrapper));
            _tpmManager = tpmManager ?? throw new ArgumentNullException(nameof(tpmManager));
            _encryptionManager = new KeyEncryptionManager(_tpmKeyWrapper);
        }

        private static (byte[] EphemeralPublicKey, byte[] SharedSecret) HandleKeyAgreementWithEphemeralPublicKey(
            KeyWrappingAgreementAlgorithm algorithm,
            byte[] recipientPublicKey)
        {
            if (recipientPublicKey == null || recipientPublicKey.Length == 0)
                throw new ArgumentException("Recipient public key is required.", nameof(recipientPublicKey));

            var sharedSecret = KeyAgreementManager.GetSharedSecretWithEphemeralPublicKey(
                algorithm,
                recipientPublicKey,
                out byte[] ephemeralPublicKey);

            ValidateSharedSecret(sharedSecret);

            return (ephemeralPublicKey, sharedSecret);
        }

        private static byte[] HandleKeyAgreementWithPrivateKey(
            KeyWrappingAgreementAlgorithm algorithm,
            byte[] ephemeralPublicKey,
            byte[] recipientPrivateKey)
        {
            if (ephemeralPublicKey == null || ephemeralPublicKey.Length == 0)
                throw new ArgumentException("Ephemeral public key is required.", nameof(ephemeralPublicKey));

            if (recipientPrivateKey == null || recipientPrivateKey.Length == 0)
                throw new ArgumentException("Recipient private key is required.", nameof(recipientPrivateKey));

            var sharedSecret = KeyAgreementManager.GetSharedSecretWithRecipientPrivateKey(
                algorithm,
                ephemeralPublicKey,
                recipientPrivateKey);

            ValidateSharedSecret(sharedSecret);

            return sharedSecret;
        }

        private static void ValidateSharedSecret(byte[] sharedSecret)
        {
            if (sharedSecret == null || sharedSecret.Length == 0)
                throw new CryptographicException("Key agreement produced an empty shared secret.");

            var allZero = new byte[sharedSecret.Length];
            if (CryptographicOperations.FixedTimeEquals(sharedSecret, allZero))
                throw new CryptographicException("Key agreement produced an invalid all-zero shared secret.");
        }

        private static KeyWrappingDerivationBlob HandleKeyDerivation(
            KeyWrappingDerivationAlgorithm algorithm,
            byte[] secret,
            byte[]? info = null,
            byte[]? salt = null)
        {
            if (algorithm == KeyWrappingDerivationAlgorithm.None)
                throw new InvalidOperationException("Derivation algorithm cannot be None when handling key derivation.");

            if (secret == null || secret.Length == 0)
                throw new ArgumentException("Secret material is required for key derivation.", nameof(secret));

            return algorithm switch
            {
                KeyWrappingDerivationAlgorithm.HKDF_SHA256 =>
                    KeyDerivationManager.DeriveKey(algorithm, secret, info, salt),

                KeyWrappingDerivationAlgorithm.Argon2Id =>
                    KeyDerivationManager.DeriveKey(algorithm, secret, null, salt),

                _ => throw new InvalidOperationException("Unsupported key derivation algorithm.")
            };
        }

        private KeyWrappingEncryptionBlob HandleKeyEncryption(
            KeyWrappingKeySource encryptionSource,
            KeyWrappingEncryptionAlgorithm algorithm,
            byte[] keyToEncrypt,
            byte[]? encryptionKey,
            byte[]? additionalData)
        {
            return _encryptionManager.Encrypt(
                encryptionSource,
                algorithm,
                keyToEncrypt,
                encryptionKey,
                additionalData);
        }

        private byte[] HandleDecryption(
            KeyWrappingKeySource source,
            KeyWrappingEncryptionAlgorithm algorithm,
            byte[]? wrappedKey,
            byte[]? decryptionKey,
            byte[]? nonce,
            byte[]? aad,
            TPMKeyBlob? tpmKeyBlob)
        {
            return _encryptionManager.Decrypt(
                source,
                algorithm,
                wrappedKey,
                decryptionKey,
                nonce,
                aad,
                tpmKeyBlob);
        }

        private byte[] ConstructAad(
            Guid keyId,
            Guid wrappingKeyId,
            string info,
            KeyWrappingProfile profile,
            KeyWrappingAgreementAlgorithm agreementAlgorithm,
            KeyWrappingDerivationAlgorithm derivationAlgorithm,
            KeyWrappingEncryptionAlgorithm encryptionAlgorithm,
            KeyWrappingKeySource keySource)
        {
            var aadObject = new
            {
                Version = 1,
                KeyId = keyId,
                WrappingKeyId = wrappingKeyId,
                WrapInfo = info,
                DeviceId = Convert.ToHexString(_tpmManager.GetEndorsementKeyHash()),
                Profile = profile.ToString(),
                AgreementAlgorithm = agreementAlgorithm.ToString(),
                DerivationAlgorithm = derivationAlgorithm.ToString(),
                EncryptionAlgorithm = encryptionAlgorithm.ToString(),
                KeySource = keySource.ToString()
            };

            string aadJson = System.Text.Json.JsonSerializer.Serialize(aadObject);
            return Encoding.UTF8.GetBytes(aadJson);
        }

        public KeyWrap Wrap(
            KeyWrappingProfile profile,
            Guid keyId,
            Guid wrappingKeyId,
            byte[] key,
            byte[] wrappingMaterial,
            string info)
        {
            if (key == null || key.Length == 0)
                throw new ArgumentException("Key to wrap is required.", nameof(key));

            if (wrappingMaterial == null || wrappingMaterial.Length == 0)
                throw new ArgumentException("Wrapping material is required.", nameof(wrappingMaterial));

            info ??= string.Empty;

            var metadata = KeyWrappingMetadata.From(profile);

            byte[] encryptionMaterial = wrappingMaterial;
            byte[]? sharedSecret = null;
            byte[]? derivedKey = null;
            byte[]? infoBytes = null;
            byte[]? aad = null;
            byte[]? ephemeralPublicKey = null;
            KeyWrappingDerivationBlob? derivationBlob = null;

            try
            {
                if (metadata.AgreementAlgorithm != KeyWrappingAgreementAlgorithm.None)
                {
                    (ephemeralPublicKey, sharedSecret) = HandleKeyAgreementWithEphemeralPublicKey(
                        metadata.AgreementAlgorithm,
                        wrappingMaterial);

                    encryptionMaterial = sharedSecret;
                }

                if (metadata.DerivationAlgorithm != KeyWrappingDerivationAlgorithm.None)
                {
                    infoBytes = Encoding.UTF8.GetBytes(info);

                    derivationBlob = HandleKeyDerivation(
                        metadata.DerivationAlgorithm,
                        encryptionMaterial,
                        infoBytes);

                    derivedKey = derivationBlob.Key;
                    encryptionMaterial = derivedKey;
                }

                aad = ConstructAad(
                    keyId,
                    wrappingKeyId,
                    info,
                    profile,
                    metadata.AgreementAlgorithm,
                    metadata.DerivationAlgorithm,
                    metadata.EncryptionAlgorithm,
                    metadata.Source);

                KeyWrappingEncryptionBlob encryptionBlob = HandleKeyEncryption(
                    metadata.Source,
                    metadata.EncryptionAlgorithm,
                    key,
                    encryptionMaterial,
                    aad);

                return profile switch
                {
                    KeyWrappingProfile.TpmAes128 => KeyWrap.CreateTpmAes128(
                        keyId,
                        encryptionBlob.TPMWrapKeyResult?.Ciphertext
                            ?? throw new InvalidOperationException("Ciphertext is required for TPM-based key wrapping."),
                        _tpmManager.GetEndorsementKeyHash(),
                        encryptionBlob.TPMWrapKeyResult
                            ?? throw new InvalidOperationException("TPM key blob is required for TPM-based key wrapping.")),

                    KeyWrappingProfile.TpmAes256 => KeyWrap.CreateTpmAes256(
                        keyId,
                        encryptionBlob.TPMWrapKeyResult?.Ciphertext
                            ?? throw new InvalidOperationException("Ciphertext is required for TPM-based key wrapping."),
                        _tpmManager.GetEndorsementKeyHash(),
                        encryptionBlob.TPMWrapKeyResult
                            ?? throw new InvalidOperationException("TPM key blob is required for TPM-based key wrapping.")),

                    KeyWrappingProfile.PassphraseArgon2IdXChaCha20Poly1305 => KeyWrap.CreatePassphraseArgon2IdXChaCha20Poly1305(
                        keyId,
                        encryptionBlob.Ciphertext
                            ?? throw new InvalidOperationException("Ciphertext is required for Argon2 key wrapping."),
                        encryptionBlob.Nonce
                            ?? throw new InvalidOperationException("Nonce is required for Argon2 key wrapping."),
                        encryptionBlob.Aad
                            ?? throw new InvalidOperationException("AAD is required for Argon2 key wrapping."),
                        derivationBlob?.Salt
                            ?? throw new InvalidOperationException("Salt is required for Argon2 key wrapping."),
                        derivationBlob?.MemLimit
                            ?? throw new InvalidOperationException("Argon2 memory is required for Argon2 key wrapping."),
                        derivationBlob?.OpsLimit
                            ?? throw new InvalidOperationException("Argon2 iterations are required for Argon2 key wrapping.")),

                    KeyWrappingProfile.PublicKeyX25519HkdfXChaCha20Poly1305 => KeyWrap.CreatePublicKeyX25519HkdfXChaCha20Poly1305(
                        keyId,
                        encryptionBlob.Ciphertext
                            ?? throw new InvalidOperationException("Ciphertext is required for public key wrapping."),
                        encryptionBlob.Nonce
                            ?? throw new InvalidOperationException("Nonce is required for public key wrapping."),
                        encryptionBlob.Aad
                            ?? throw new InvalidOperationException("AAD is required for public key wrapping."),
                        derivationBlob?.Salt
                            ?? throw new InvalidOperationException("Salt is required for public key wrapping."),
                        derivationBlob?.Info
                            ?? throw new InvalidOperationException("HKDF info is required for public key wrapping."),
                        ephemeralPublicKey
                            ?? throw new InvalidOperationException("Ephemeral public key is required for public key wrapping.")),

                    KeyWrappingProfile.ParentKeyXChaCha20Poly1305 => KeyWrap.CreateParentKeyXChaCha20Poly1305(
                        keyId,
                        wrappingKeyId,
                        encryptionBlob.Ciphertext
                            ?? throw new InvalidOperationException("Ciphertext is required for parent key wrapping."),
                        encryptionBlob.Nonce
                            ?? throw new InvalidOperationException("Nonce is required for parent key wrapping."),
                        encryptionBlob.Aad
                            ?? throw new InvalidOperationException("AAD is required for parent key wrapping.")),

                    _ => throw new InvalidOperationException("Unsupported key wrapping profile.")
                };
            }
            finally
            {
                ZeroIfNotNull(sharedSecret);
                ZeroIfNotNull(derivedKey);
                ZeroIfNotNull(infoBytes);
            }
        }

        public byte[] Unwrap(KeyWrap wrap, byte[] unwrappingMaterial)
        {
            if (wrap == null)
                throw new ArgumentNullException(nameof(wrap));

            if (unwrappingMaterial == null || unwrappingMaterial.Length == 0)
                throw new ArgumentException("Unwrapping material is required.", nameof(unwrappingMaterial));

            var metadata = KeyWrappingMetadata.From(wrap.Profile);

            byte[] decryptionMaterial = unwrappingMaterial;
            byte[]? sharedSecret = null;
            byte[]? derivedKey = null;
            KeyWrappingDerivationBlob? derivationBlob = null;

            try
            {
                if (metadata.AgreementAlgorithm != KeyWrappingAgreementAlgorithm.None)
                {
                    sharedSecret = HandleKeyAgreementWithPrivateKey(
                        metadata.AgreementAlgorithm,
                        wrap.EphemeralPublicKey
                            ?? throw new InvalidOperationException("Ephemeral public key is required for unwrapping with key agreement."),
                        unwrappingMaterial);

                    decryptionMaterial = sharedSecret;
                }

                if (metadata.DerivationAlgorithm != KeyWrappingDerivationAlgorithm.None)
                {
                    derivationBlob = HandleKeyDerivation(
                        metadata.DerivationAlgorithm,
                        decryptionMaterial,
                        wrap.Info,
                        wrap.Salt);

                    derivedKey = derivationBlob.Key;
                    decryptionMaterial = derivedKey;
                }

                byte[] decryptedKey = HandleDecryption(
                    wrap.Metadata.Source,
                    wrap.Metadata.EncryptionAlgorithm,
                    wrap.WrappedKey,
                    decryptionMaterial,
                    wrap.Nonce,
                    wrap.Aad,
                    wrap.TPMKeyBlob);

                if (decryptedKey == null || decryptedKey.Length == 0)
                    throw new InvalidOperationException("Decryption failed. Decrypted key is empty.");

                return decryptedKey;
            }
            finally
            {
                ZeroIfNotNull(sharedSecret);
                ZeroIfNotNull(derivedKey);
            }
        }

        private static void ZeroIfNotNull(byte[]? buffer)
        {
            if (buffer != null)
                CryptographicOperations.ZeroMemory(buffer);
        }
    }
}
