using Sodium.Exceptions;
using Synccl.Core.Enums.KeyWrapping;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Model.Security
{
    public class KeyWrappingDerivationBlob
    {
        public KeyWrappingDerivationAlgorithm Algorithm { get; private set; }
        public byte[] Key { get; private set; }
        public byte[] Salt { get; private set; }
        public int OutputLength { get; private set; }
        public int? OpsLimit 
        { 
            get
            {
                if (Algorithm == KeyWrappingDerivationAlgorithm.Argon2Id)
                {
                    return field;
                }
                return null;
            }
            private set
            {
                if (Algorithm == KeyWrappingDerivationAlgorithm.Argon2Id)
                {
                    field = value;
                }
            }
        }

        public int? MemLimit
        {
            get
            {
                if (Algorithm == KeyWrappingDerivationAlgorithm.Argon2Id)
                {
                    return field;
                }
                return null;
            }
            private set
            {
                if (Algorithm == KeyWrappingDerivationAlgorithm.Argon2Id)
                {
                    field = value;
                }
            }
        }

        public byte[]? Info
        {
            get
            {
                if (Algorithm == KeyWrappingDerivationAlgorithm.HKDF_SHA256)
                {
                    return field;
                }
                return null;
            }
            private set
            {
                if (Algorithm == KeyWrappingDerivationAlgorithm.HKDF_SHA256)
                {
                    field = value;
                }
            }
        }

        public KeyWrappingDerivationBlob(
            KeyWrappingDerivationAlgorithm algorithm,
            byte[] key, 
            byte[] salt, 
            int outputLength, 
            int? opsLimit = null, 
            int? memLimit = null,
            byte[]? info = null)
        {
            if (algorithm == KeyWrappingDerivationAlgorithm.None)
                throw new ArgumentException("Key derivation algorithm must be specified and cannot be None.", nameof(Algorithm));

            if (key == null || key.Length == 0) 
                throw new ArgumentException("Key cannot be null or empty.", nameof(key));

            if (salt == null || salt.Length == 0) 
                throw new ArgumentException("Salt cannot be null or empty.", nameof(salt));

            if (outputLength <= 16) 
                throw new ArgumentOutOfRangeException(nameof(outputLength), "Output length must be greater than 16.");

            if (opsLimit != null && algorithm != KeyWrappingDerivationAlgorithm.Argon2Id)
                throw new ArgumentException("Ops limit is only applicable for Argon2id key derivation and should be null for other algorithms.", nameof(opsLimit));

            if (opsLimit != null && opsLimit < 4)
                throw new ArgumentOutOfRangeException(nameof(opsLimit), "Ops limit must be greater than 4.");

            if (memLimit != null && algorithm != KeyWrappingDerivationAlgorithm.Argon2Id)
                throw new ArgumentException("Memory limit is only applicable for Argon2id key derivation and should be null for other algorithms.", nameof(memLimit));

            if (memLimit != null && memLimit < 1 << 28)
                throw new ArgumentOutOfRangeException(nameof(memLimit), "Memory limit must be greater than 256 MiB.");

            if (info != null && algorithm != KeyWrappingDerivationAlgorithm.HKDF_SHA256)
                throw new ArgumentException("Info parameter is only applicable for HKDF key derivation and should be null for other algorithms.", nameof(info));

            if (info != null && info.Length == 0)
                throw new ArgumentException("Info parameter cannot be empty if provided.", nameof(info));

            Algorithm = algorithm;
            Key = key;
            Salt = salt;
            OutputLength = outputLength;
            OpsLimit = opsLimit;
            MemLimit = memLimit;
            Info = info;
        }
    }
}
