using Sodium;
using Synccl.Core.Enums.KeyWrapping;
using Synccl.Core.Model.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Security
{
    public class KeyDerivationManager
    {
        public static KeyWrappingDerivationBlob DeriveKey(
            KeyWrappingDerivationAlgorithm algorithm, 
            byte[] secret, 
            byte[]? info,
            byte[]? salt = null)
        {
            if (algorithm == KeyWrappingDerivationAlgorithm.None)
            {
                throw new InvalidOperationException("Key derivation algorithm is set to None. Please specify a valid algorithm.");
            }

            if (algorithm == KeyWrappingDerivationAlgorithm.Argon2Id)
            {
                if (info != null)
                {
                    throw new ArgumentException("Info parameter is not used for Argon2id key derivation and should be null.", nameof(info));
                }

                return DeriveArgon2IdKey(algorithm, secret, salt);
            }
            else if (algorithm == KeyWrappingDerivationAlgorithm.HKDF_SHA256)
            {
                if (info == null)
                {
                    throw new ArgumentNullException(nameof(info), "Info parameter is required for HKDF key derivation.");
                }

                return DeriveHKDFKey(algorithm, secret, info, salt);
            }
            else 
            {
                throw new InvalidOperationException("Unsupported key derivation algorithm.");
            }
        }

        private static KeyWrappingDerivationBlob DeriveArgon2IdKey(
            KeyWrappingDerivationAlgorithm algorithm, 
            byte[] secret, byte[]? salt = null)
        {
            if (salt == null)
            {
                salt = new byte[16];
                RandomNumberGenerator.Fill(salt);
            }

            var key = PasswordHash.ArgonHashBinary(
                password: secret,
                salt: salt,
                opsLimit: 4,
                memLimit: 1 << 28,
                outputLength: 32); 

            return new KeyWrappingDerivationBlob(algorithm, key, salt, 32, 4, 1 << 28);
        }

        private static KeyWrappingDerivationBlob DeriveHKDFKey(
            KeyWrappingDerivationAlgorithm algorithm,
            byte[] secret,
            byte[] info,
            byte[]? salt = null)
        {
            if (salt == null)
            {
                salt = new byte[16];
                RandomNumberGenerator.Fill(salt);
            }

            var key = HKDF.DeriveKey(
                HashAlgorithmName.SHA256,
                secret,
                32,
                salt,
                info);
            return new KeyWrappingDerivationBlob(algorithm, key, salt, 32);
        }
    }
}
