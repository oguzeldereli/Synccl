using Synccl.Core.Enums.KeyWrapping;
using Synccl.Core.Interfaces.Security;
using Synccl.Core.Model.Security;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Tpm2Lib;

namespace Synccl.Cli.Security
{
    /// <summary>
    /// TPM 2.0 key wrapper for Windows and Linux.
    ///
    /// Key hierarchy:
    ///   Owner storage primary  (RSA-2048, deterministic - same key on every boot)
    ///     └─ AES-256 CFB child key  (TPM2_Create once, blobs stored on disk)
    ///
    /// Why no EvictControl:
    ///   Windows TBS does not allow ordinary callers to use EvictControl on the
    ///   owner hierarchy.  Instead the TpmPrivate + TpmPublic blobs are written to
    ///   the user config directory.  On every Wrap/Unwrap the deterministic storage
    ///   primary is re-derived and the AES key is reloaded as a transient object,
    ///   used, then immediately flushed.
    ///
    /// Storage:
    ///   %APPDATA%\synccl\tpm_key.pub   (TpmPublic blob - not secret)
    ///   %APPDATA%\synccl\tpm_key.priv  (TpmPrivate blob - TPM-encrypted, safe to store)
    ///   (~/.config/synccl/ on Linux)
    ///
    /// TPMKeyBlob field usage:
    ///   Ciphertext     - EncryptDecrypt output (TPM-sealed vault master key)
    ///   Iv             - TPM-returned CFB IV (required for decryption)
    ///   TpmPublicBlob  - AES key TpmPublic blob (device binding / identity check)
    ///   TpmPrivateBlob - empty (blobs are stored globally in the config dir, not per-blob)
    /// </summary>
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    public sealed class TpmKeyWrapper : ITPMKeyWrapper, IDisposable
    {
        // ------------------------------------------------------------------ //
        //  TPM key templates
        // ------------------------------------------------------------------ //

        // RSA-2048 restricted storage primary.
        // Fixed template makes CreatePrimary deterministic: the TPM re-derives
        // the same key from its seed on every call.
        private static readonly TpmPublic StoragePrimaryTemplate = new(
            TpmAlgId.Sha256,
            ObjectAttr.FixedTPM | ObjectAttr.FixedParent |
            ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin |
            ObjectAttr.Decrypt | ObjectAttr.Restricted,
            [],
            new RsaParms(
                new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb),
                new NullAsymScheme(), 2048, 65537),
            new Tpm2bPublicKeyRsa([]));

        // AES-256 CFB symmetric key - created once under the storage primary.
        private static readonly TpmPublic Aes256KeyTemplate = new(
            TpmAlgId.Sha256,
            ObjectAttr.FixedTPM | ObjectAttr.FixedParent |
            ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin |
            ObjectAttr.Decrypt | ObjectAttr.Sign,
            [],
            new SymcipherParms(
                new SymDefObject(TpmAlgId.Aes, 256, TpmAlgId.Cfb)),
            new Tpm2bDigestSymcipher([]));

        // ------------------------------------------------------------------ //
        //  Fields
        // ------------------------------------------------------------------ //

        private readonly Tpm2 _tpm;
        private readonly Tpm2Device _device;

        // The TpmPublic blob is kept for device-identity checks (GetAesKeyPublicBlob).
        private readonly byte[] _aesPublicBlob;

        // Transient AES-256 key loaded once at construction and reused for every
        // Wrap/Unwrap call.  This avoids one CreatePrimary + one Load per operation.
        private readonly TpmHandle _transientAesKey;

        private bool _disposed;

        // ------------------------------------------------------------------ //
        //  Construction
        // ------------------------------------------------------------------ //

        public TpmKeyWrapper()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                _device = new LinuxTpmDevice();
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                _device = new TbsDevice();
            else
                throw new PlatformNotSupportedException(
                    "TpmKeyWrapper requires Windows or Linux.");

            _device.Connect();
            _tpm = new Tpm2(_device);

            (_aesPublicBlob, _transientAesKey) = LoadOrCreateAesKey();
        }

        // ------------------------------------------------------------------ //
        //  ITPMKeyWrapper
        // ------------------------------------------------------------------ //

        public TPMKeyBlob Wrap(byte[] keyMaterial)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(TpmKeyWrapper));
            if (keyMaterial is null || keyMaterial.Length == 0)
                throw new ArgumentException("Key material is required.", nameof(keyMaterial));

            byte[] ivIn = new byte[16];
            System.Security.Cryptography.RandomNumberGenerator.Fill(ivIn);
            byte[] ciphertext = _tpm.EncryptDecrypt(
                _transientAesKey,
                1,
                TpmAlgId.Cfb,
                ivIn,
                keyMaterial,
                out _);

            return TPMKeyBlob.Create(
                ciphertext,
                ivIn,
                tpmPublicBlob: _aesPublicBlob,
                tpmPrivateBlob: [],
                KeyWrappingEncryptionAlgorithm.AES_256);
        }

        public byte[] Unwrap(TPMKeyBlob wrappedKey)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(TpmKeyWrapper));
            if (wrappedKey is null) throw new ArgumentNullException(nameof(wrappedKey));

            return _tpm.EncryptDecrypt(
                _transientAesKey,
                0,
                TpmAlgId.Cfb,
                wrappedKey.Iv,
                wrappedKey.Ciphertext,
                out _);
        }

        // ------------------------------------------------------------------ //
        //  Device identity accessor (used by TpmManager)
        // ------------------------------------------------------------------ //

        /// <summary>Returns the stored TpmPublic blob used as the device binding hash input.</summary>
        public byte[] GetAesKeyPublicBlob() => _aesPublicBlob;

        // ------------------------------------------------------------------ //
        //  Key provisioning
        // ------------------------------------------------------------------ //

        // ------------------------------------------------------------------ //
        //  Key provisioning
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Loads (or creates) the AES-256 key blobs from disk, then loads the key
        /// as a transient object under a freshly re-derived storage primary.
        /// The primary is flushed immediately after Load — it is only needed to
        /// authorise the Load/Create commands.  The returned transient handle
        /// stays loaded for the lifetime of this object.
        /// </summary>
        private (byte[] pubBlob, TpmHandle transient) LoadOrCreateAesKey()
        {
            string configDir = GetConfigDirectory();
            string pubFile   = Path.Combine(configDir, "tpm_key.pub");
            string privFile  = Path.Combine(configDir, "tpm_key.priv");

            // One CreatePrimary — the only one we ever do per process.
            TpmHandle primary = CreateStoragePrimary();
            try
            {
                if (File.Exists(pubFile) && File.Exists(privFile))
                {
                    byte[] pubBytes  = File.ReadAllBytes(pubFile);
                    byte[] privBytes = File.ReadAllBytes(privFile);

                    try
                    {
                        var pub  = Marshaller.FromTpmRepresentation<TpmPublic>(pubBytes);
                        var priv = Marshaller.FromTpmRepresentation<TpmPrivate>(privBytes);
                        TpmHandle transient = _tpm.Load(primary, priv, pub);
                        // Successfully loaded — return immediately (primary flushed in finally).
                        return (pubBytes, transient);
                    }
                    catch
                    {
                        // Blobs invalid (different TPM / re-provisioned) — fall through to re-create.
                    }
                }

                // First-time or invalid blobs: create a new AES key under the same primary.
                TpmPrivate aesPriv = _tpm.Create(
                    primary,
                    new SensitiveCreate(),
                    Aes256KeyTemplate,
                    [], [],
                    out TpmPublic aesPub,
                    out _, out _, out _);

                byte[] newPubBlob  = aesPub.GetTpmRepresentation();
                byte[] newPrivBlob = aesPriv.GetTpmRepresentation();

                Directory.CreateDirectory(configDir);
                File.WriteAllBytes(pubFile,  newPubBlob);
                File.WriteAllBytes(privFile, newPrivBlob);

                TpmHandle newTransient = _tpm.Load(
                    primary,
                    Marshaller.FromTpmRepresentation<TpmPrivate>(newPrivBlob),
                    Marshaller.FromTpmRepresentation<TpmPublic>(newPubBlob));

                return (newPubBlob, newTransient);
            }
            finally
            {
                // Primary only needed for Load/Create; flush now.
                try { _tpm.FlushContext(primary); } catch { }
            }
        }

        private TpmHandle CreateStoragePrimary() =>
            _tpm.CreatePrimary(
                TpmRh.Owner,
                new SensitiveCreate(),
                StoragePrimaryTemplate,
                [], [],
                out _,
                out _,
                out _,
                out _);

        // ------------------------------------------------------------------ //
        //  Config directory
        // ------------------------------------------------------------------ //

        private static string GetConfigDirectory()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "synccl");

            // Linux: respect XDG_CONFIG_HOME
            string xdg = Environment.GetEnvironmentVariable("XDG_CONFIG_HOME")
                ?? Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".config");
            return Path.Combine(xdg, "synccl");
        }

        // ------------------------------------------------------------------ //
        //  Disposal
        // ------------------------------------------------------------------ //

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            try { _tpm.FlushContext(_transientAesKey); } catch { }
            try { _tpm?.Dispose(); } catch { }
            try { _device?.Dispose(); } catch { }
        }
    }
}
