using Synccl.Core.Interfaces.Security;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Synccl.Cli.Security
{
    /// <summary>
    /// macOS device identity derived from the Secure Enclave P-256 key.
    /// The SHA-256 hash of the SE public key SPKI is stable for the lifetime
    /// of the key in the Secure Enclave (i.e. until explicitly deleted).
    /// </summary>
    [SupportedOSPlatform("macos")]
    public sealed class MacSecureEnclaveManager : ITPMManager
    {
        private byte[]? _idHash;

        public byte[] GetEndorsementKeyHash()
        {
            if (_idHash is not null) return _idHash;

            try
            {
                // Reuse the SE helper from the key wrapper.
                IntPtr priv = MacSecureEnclaveKeyWrapper.SE.GetOrCreatePrivateKey(
                    "com.synccl.vault.sealingkey");
                IntPtr pub = MacSecureEnclaveKeyWrapper.SE.CopyPublicKey(priv);
                byte[] spki = MacSecureEnclaveKeyWrapper.SE.ExportPublicKey(pub);
                _idHash = SHA256.HashData(spki);
            }
            catch
            {
                // Fallback if SE not available (e.g. CI / non-SE Mac).
                _idHash = SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(
                        $"synccl|{Environment.MachineName}|se-fallback"));
            }

            return _idHash;
        }
    }
}
