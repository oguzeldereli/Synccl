using Synccl.Core.Interfaces.Security;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Tpm2Lib;

namespace Synccl.Cli.Security
{
    /// <summary>
    /// TPM-backed ITPMManager for Windows and Linux.
    ///
    /// <see cref="GetEndorsementKeyHash"/> derives a stable, device-unique 32-byte
    /// identifier by reading the TPM Endorsement Key (EK) public area and hashing it
    /// with SHA-256.  The EK is fixed per device and TPM, so the hash is stable across
    /// reboots and re-provisions of app keys.
    ///
    /// If reading the EK fails (e.g. no EK provisioned or insufficient auth), we fall
    /// back to the platform-specific machine name hash so the app still functions.
    /// </summary>
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    public sealed class TpmManager : ITPMManager, IDisposable
    {
        private readonly Tpm2 _tpm;
        private readonly Tpm2Device _device;
        private byte[]? _ekHash;
        private bool _disposed;

        public TpmManager()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                _device = new LinuxTpmDevice();
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                _device = new TbsDevice();
            else
                throw new PlatformNotSupportedException("TpmManager requires Windows or Linux.");

            _device.Connect();
            _tpm = new Tpm2(_device);
        }

        /// <summary>
        /// Returns a stable 32-byte device identity derived from the TPM EK public area.
        /// The same value is returned for all calls on the same device.
        /// </summary>
        public byte[] GetEndorsementKeyHash()
        {
            if (_ekHash is not null) return _ekHash;

            try
            {
                // The default EK handle is 0x81010001 (RSA EK persistent handle per TCG spec).
                var ekHandle = new TpmHandle(0x81010001u);
                TpmPublic ekPub = _tpm.ReadPublic(ekHandle, out _, out _);
                byte[] ekPubBlob = ekPub.GetTpmRepresentation();
                _ekHash = SHA256.HashData(ekPubBlob);
            }
            catch
            {
                // EK not provisioned or not accessible — derive a machine-scoped fallback.
                _ekHash = FallbackHash();
            }

            return _ekHash;
        }

        private static byte[] FallbackHash()
        {
            var material = System.Text.Encoding.UTF8.GetBytes(
                $"synccl|{Environment.MachineName}|tpm-fallback");
            return SHA256.HashData(material);
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            try { _tpm?.Dispose(); } catch { }
            try { _device?.Dispose(); } catch { }
        }
    }
}
