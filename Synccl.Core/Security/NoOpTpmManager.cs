using Synccl.Core.Interfaces.Security;
using System.Security.Cryptography;

namespace Synccl.Core.Security
{
    /// <summary>
    /// TPM manager stub that derives a stable machine-scoped endorsement key hash
    /// from the local machine name when a real TPM is unavailable.
    /// </summary>
    public sealed class NoOpTpmManager : ITPMManager
    {
        public byte[] GetEndorsementKeyHash()
        {
            var material = System.Text.Encoding.UTF8.GetBytes(
                Environment.MachineName + "|synccl-ek");
            return SHA256.HashData(material);
        }
    }
}
