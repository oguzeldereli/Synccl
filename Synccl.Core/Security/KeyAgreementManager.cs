using Sodium;
using Synccl.Core.Enums.KeyWrapping;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Security
{
    public class KeyAgreementManager
    {
        public static byte[] GetSharedSecretWithEphemeralPublicKey(
            KeyWrappingAgreementAlgorithm algorithm,
            byte[] recipientPublicKey, 
            out byte[] ephemeralPublicKey)
        {
            if (algorithm == KeyWrappingAgreementAlgorithm.None)
            {
                throw new InvalidOperationException("Key agreement algorithm is not specified.");
            }

            var ephemeralKeyPair = PublicKeyBox.GenerateKeyPair();
            var sharedSecret = ScalarMult.Mult(ephemeralKeyPair.PrivateKey, recipientPublicKey);
            CryptographicOperations.ZeroMemory(ephemeralKeyPair.PrivateKey);
            ephemeralPublicKey = ephemeralKeyPair.PublicKey;
            return sharedSecret;
        }

        public static byte[] GetSharedSecretWithRecipientPrivateKey(
            KeyWrappingAgreementAlgorithm algorithm,
            byte[] ephemeralPublicKey,
            byte[] recipientPrivateKey)
        {
            if (algorithm == KeyWrappingAgreementAlgorithm.None)
            {
                throw new InvalidOperationException("Key agreement algorithm is not specified.");
            }

            var sharedSecret = ScalarMult.Mult(recipientPrivateKey, ephemeralPublicKey);
            return sharedSecret;
        }
    }
}
