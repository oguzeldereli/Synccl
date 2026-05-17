using Synccl.Core.Entities.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Entities.Model.Security
{
    public class EncryptedBlob
    {
        public DataEncryptionAlgorithm Algorithm { get; private set; }
        public byte[] Ciphertext { get; private set; }
        public byte[] Nonce { get; private set; }
        public byte[] Aad { get; private set; }
        public byte[] Tag { get; private set; }

        private EncryptedBlob(DataEncryptionAlgorithm algorithm, byte[] ciphertext, byte[] nonce, byte[] aad, byte[] tag)
        {
            if (ciphertext == null || ciphertext.Length == 0)
                throw new ArgumentException("Ciphertext cannot be null or empty.", nameof(ciphertext));
            if (nonce == null || nonce.Length == 0)
                throw new ArgumentException("Nonce cannot be null or empty.", nameof(nonce));
            if (aad == null || aad.Length == 0)
                throw new ArgumentException("AAD cannot be null or empty.", nameof(aad));
            if (tag == null || tag.Length == 0)
                throw new ArgumentException("Tag cannot be null or empty.", nameof(tag));

            Algorithm = algorithm;
            Ciphertext = ciphertext;
            Nonce = nonce;
            Aad = aad;
            Tag = tag;
        }

        public static EncryptedBlob Create(DataEncryptionAlgorithm algorithm, byte[] ciphertext, byte[] nonce, byte[] aad, byte[] tag)
        {
            return new EncryptedBlob(algorithm, ciphertext, nonce, aad, tag);
        }

        public static EncryptedBlob From(EncryptedBlob blob)
        {
            if (blob == null)
                throw new ArgumentNullException(nameof(blob));
            return new EncryptedBlob(blob.Algorithm, blob.Ciphertext, blob.Nonce, blob.Aad, blob.Tag);
        }
    }
}
