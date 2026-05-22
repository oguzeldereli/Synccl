using Synccl.Core.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Model.Security
{
    public class Signature
    {
        public Guid SignatureId { get; set; }
        public Guid SigningKeyId { get; private set; }
        public byte[] SignatureData { get; set; }
        public ValidSigningAlgorithms Algorithm { get; private set; }
        public DateTime CreatedAt { get; private set; }

        private Signature(Guid signatureId, Guid signatureKeyId, byte[] signatureData)
        {
            SignatureId = signatureId;
            SigningKeyId = signatureKeyId;
            SignatureData = signatureData;
        }

        public static Signature Create(Guid signatureId, Guid signatureKeyId, byte[] signatureData)
        {
            if (signatureId == Guid.Empty)
                throw new ArgumentException("Signature ID cannot be empty.", nameof(signatureId));
            if (signatureKeyId == Guid.Empty)
                throw new ArgumentException("Signing Key ID cannot be empty.", nameof(signatureKeyId));
            if (signatureData == null || signatureData.Length == 0)
                throw new ArgumentException("Signature data cannot be null or empty.", nameof(signatureData));
            return new Signature(signatureId, signatureKeyId, signatureData);
        }
    }
}
