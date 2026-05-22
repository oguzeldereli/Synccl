using Synccl.Core.Enums.KeyWrapping;

namespace Synccl.Core.Model.Security
{
    public class KeyWrappingMetadata
    {
        public KeyWrappingEncryptionAlgorithm EncryptionAlgorithm { get; private set; }
        public KeyWrappingAgreementAlgorithm AgreementAlgorithm { get; private set; }
        public KeyWrappingDerivationAlgorithm DerivationAlgorithm { get; private set; }
        public KeyWrappingKeySource Source { get; private set; }

        private KeyWrappingMetadata() { }

        private static Dictionary<KeyWrappingProfile, KeyWrappingMetadata> ValidMetadata = new()
        {
            {
                KeyWrappingProfile.TpmAes128,
                new KeyWrappingMetadata
                {
                    EncryptionAlgorithm = KeyWrappingEncryptionAlgorithm.AES_128,
                    AgreementAlgorithm = KeyWrappingAgreementAlgorithm.None,
                    DerivationAlgorithm = KeyWrappingDerivationAlgorithm.None,
                    Source = KeyWrappingKeySource.TPMBlob
                }
            },
            {
                KeyWrappingProfile.TpmAes256, 
                new KeyWrappingMetadata
                {
                    EncryptionAlgorithm = KeyWrappingEncryptionAlgorithm.AES_256,
                    AgreementAlgorithm = KeyWrappingAgreementAlgorithm.None,
                    DerivationAlgorithm = KeyWrappingDerivationAlgorithm.None,
                    Source = KeyWrappingKeySource.TPMBlob
                } 
            },
            {
                KeyWrappingProfile.PassphraseArgon2IdXChaCha20Poly1305,
                new KeyWrappingMetadata
                {
                    EncryptionAlgorithm = KeyWrappingEncryptionAlgorithm.XChaCha20Poly1305,
                    AgreementAlgorithm = KeyWrappingAgreementAlgorithm.None,
                    DerivationAlgorithm = KeyWrappingDerivationAlgorithm.Argon2Id,
                    Source = KeyWrappingKeySource.Passphrase
                }
            },
            {
                KeyWrappingProfile.PublicKeyX25519HkdfXChaCha20Poly1305,
                new KeyWrappingMetadata
                {
                    EncryptionAlgorithm = KeyWrappingEncryptionAlgorithm.XChaCha20Poly1305,
                    AgreementAlgorithm = KeyWrappingAgreementAlgorithm.X25519,
                    DerivationAlgorithm = KeyWrappingDerivationAlgorithm.HKDF_SHA256,
                    Source = KeyWrappingKeySource.PublicKey
                }
            },
            {
                KeyWrappingProfile.ParentKeyXChaCha20Poly1305,
                new KeyWrappingMetadata
                {
                    EncryptionAlgorithm = KeyWrappingEncryptionAlgorithm.XChaCha20Poly1305,
                    AgreementAlgorithm = KeyWrappingAgreementAlgorithm.None,
                    DerivationAlgorithm = KeyWrappingDerivationAlgorithm.None,
                    Source = KeyWrappingKeySource.ParentKey
                }
            }
        };

        public static KeyWrappingMetadata From(KeyWrappingProfile profile)
        {
            if (!ValidMetadata.TryGetValue(profile, out var metadata))
                throw new ArgumentException($"Invalid key wrapping profile: {profile}", nameof(profile));
            return metadata;
        }

        public static KeyWrappingMetadata From(KeyWrappingMetadata metadata)
        {
            return new KeyWrappingMetadata
            {
                EncryptionAlgorithm = metadata.EncryptionAlgorithm,
                AgreementAlgorithm = metadata.AgreementAlgorithm,
                DerivationAlgorithm = metadata.DerivationAlgorithm,
                Source = metadata.Source
            };
        }
    }
}
