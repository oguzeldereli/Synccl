using Synccl.Core.Enums.KeyWrapping;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Model.Security
{
    public class TPMKeyBlob
    {
        public byte[] Ciphertext { get; private set; }
        public byte[] Iv { get; private set; }
        public byte[] TpmPublicBlob { get; private set; }
        public byte[] TpmPrivateBlob { get; private set; }
        public KeyWrappingEncryptionAlgorithm Algorithm { get; private set; }
        private TPMKeyBlob(
            byte[] ciphertext,
            byte[] iv,
            byte[] tpmPublicBlob,
            byte[] tpmPrivateBlob,
            KeyWrappingEncryptionAlgorithm algorithm)
        {
            Ciphertext = ciphertext;
            Iv = iv;
            TpmPublicBlob = tpmPublicBlob;
            TpmPrivateBlob = tpmPrivateBlob;
            Algorithm = algorithm;
        }

        public static TPMKeyBlob Create(
            byte[] ciphertext,
            byte[] iv,
            byte[] tpmPublicBlob,
            byte[] tpmPrivateBlob,
            KeyWrappingEncryptionAlgorithm algorithm)
        {
            if (ciphertext == null)
                throw new ArgumentNullException(nameof(ciphertext));

            if (iv == null)
                throw new ArgumentNullException(nameof(iv));

            if (tpmPublicBlob == null)
                throw new ArgumentNullException(nameof(tpmPublicBlob));

            if (tpmPrivateBlob == null)
                throw new ArgumentNullException(nameof(tpmPrivateBlob));

            if (algorithm != KeyWrappingEncryptionAlgorithm.AES_128 &&
                algorithm != KeyWrappingEncryptionAlgorithm.AES_256)
                throw new ArgumentException("Invalid algorithm", nameof(algorithm));

            return new TPMKeyBlob(ciphertext, iv, tpmPublicBlob, tpmPrivateBlob, algorithm);
        }

        public static TPMKeyBlob From(TPMKeyBlob blob)
        {
            if (blob == null)
                throw new ArgumentNullException(nameof(blob));
            return new TPMKeyBlob(blob.Ciphertext, blob.Iv, blob.TpmPublicBlob, blob.TpmPrivateBlob, blob.Algorithm);
        }
    }
}
