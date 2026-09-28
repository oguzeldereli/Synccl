using Synccl.Core.Interfaces.Security;

namespace Synccl.Cli.Security
{
    /// <summary>
    /// Creates the correct ITPMKeyWrapper + ITPMManager pair for the current platform:
    ///   Windows / Linux  →  TpmKeyWrapper + TpmManager  (TPM 2.0 via Microsoft.TSS)
    ///   macOS            →  MacSecureEnclaveKeyWrapper + MacSecureEnclaveManager
    ///
    /// There is no software fallback. A vault's protection is its hardware binding, so
    /// without a TPM or Secure Enclave synccl refuses to run rather than seal vaults with
    /// a key an attacker could derive.
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
                    throw new PlatformNotSupportedException(
                        $"TPM 2.0 is unavailable ({ex.Message}). synccl requires a TPM to protect vaults " +
                        "and will not run without one. On Linux, check that /dev/tpmrm0 (or /dev/tpm0) exists and that " +
                        "your user can access it (usually via the 'tss' group).", ex);
                }
            }

            if (OperatingSystem.IsMacOS())
            {
                try
                {
                    var wrapper = new MacSecureEnclaveKeyWrapper();
                    var manager = new MacSecureEnclaveManager();
                    return (wrapper, manager);
                }
                catch (Exception ex)
                {
                    throw new PlatformNotSupportedException(
                        $"The Secure Enclave is unavailable ({ex.Message}). synccl requires it to protect " +
                        "vaults and will not run without it.", ex);
                }
            }

            throw new PlatformNotSupportedException(
                "synccl requires a TPM 2.0 (Windows, Linux) or the Secure Enclave (macOS) and does not " +
                "support this platform.");
        }
    }
}
