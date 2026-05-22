using Synccl.Core.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Model.Security
{
    public class EncryptedDataBlob
    {
        public DataEncryptionAlgorithm Algorithm { get; private set; }
        public byte[] Ciphertext { get; private set; }
        public byte[] Nonce { get; private set; }
        public byte[] Aad { get; private set; }

        private EncryptedDataBlob(DataEncryptionAlgorithm algorithm, byte[] ciphertext, byte[] nonce, byte[] aad)
        {
            if (ciphertext == null || ciphertext.Length == 0)
                throw new ArgumentException("Ciphertext cannot be null or empty.", nameof(ciphertext));
            if (nonce == null || nonce.Length == 0)
                throw new ArgumentException("Nonce cannot be null or empty.", nameof(nonce));
            if (aad == null || aad.Length == 0)
                throw new ArgumentException("AAD cannot be null or empty.", nameof(aad));

            Algorithm = algorithm;
            Ciphertext = ciphertext;
            Nonce = nonce;
            Aad = aad;
        }

        public static EncryptedDataBlob Create(DataEncryptionAlgorithm algorithm, byte[] ciphertext, byte[] nonce, byte[] aad)
        {
            return new EncryptedDataBlob(algorithm, ciphertext, nonce, aad);
        }

        public static EncryptedDataBlob From(EncryptedDataBlob blob)
        {
            if (blob == null)
                throw new ArgumentNullException(nameof(blob));
            return new EncryptedDataBlob(blob.Algorithm, blob.Ciphertext, blob.Nonce, blob.Aad);
        }
    }
}
