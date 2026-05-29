using Synccl.Core.Interfaces.Security;
using Synccl.Core.Security;
using System.Runtime.InteropServices;

namespace Synccl.Cli.Security
{
    /// <summary>
    /// Creates the correct ITPMKeyWrapper + ITPMManager pair for the current platform:
    ///   Windows / Linux  →  TpmKeyWrapper + TpmManager  (TPM 2.0 via Microsoft.TSS)
    ///   macOS            →  MacSecureEnclaveKeyWrapper + MacSecureEnclaveManager
    ///   Other            →  NoOpTpmKeyWrapper + NoOpTpmManager  (software fallback)
    /// </summary>
    public static class PlatformTpmFactory
    {
        public static (ITPMKeyWrapper KeyWrapper, ITPMManager Manager) Create()
        {
            if (OperatingSystem.IsWindows() || OperatingSystem.IsLinux())
            {
                try
                {
                    var wrapper = new TpmKeyWrapper();
                    var manager = new TpmManager();
                    return (wrapper, manager);
                }
                catch (Exception ex)
                {
                    // TPM not available or not accessible — fall through to software stub.
                    Console.Error.WriteLine(
                        $"[synccl] Warning: TPM unavailable ({ex.Message}). " +
                        "Falling back to software key protection.");
                }
            }
            else if (OperatingSystem.IsMacOS())
            {
                try
                {
                    var wrapper = new MacSecureEnclaveKeyWrapper();
                    var manager = new MacSecureEnclaveManager();
                    return (wrapper, manager);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine(
                        $"[synccl] Warning: Secure Enclave unavailable ({ex.Message}). " +
                        "Falling back to software key protection.");
                }
            }

            // Software fallback (DPAPI / machine-scoped AES-GCM).
            return (new NoOpTpmKeyWrapper(), new NoOpTpmManager());
        }
    }
}
