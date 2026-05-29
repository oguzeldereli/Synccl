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

        // Serialised blobs stored on disk; loaded once at construction.
        private readonly byte[] _aesPublicBlob;
        private readonly byte[] _aesPrivateBlob;

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

            (_aesPublicBlob, _aesPrivateBlob) = LoadOrCreateAesKeyBlobs();
        }

        // ------------------------------------------------------------------ //
        //  ITPMKeyWrapper
        // ------------------------------------------------------------------ //

        public TPMKeyBlob Wrap(byte[] keyMaterial)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(TpmKeyWrapper));
            if (keyMaterial is null || keyMaterial.Length == 0)
                throw new ArgumentException("Key material is required.", nameof(keyMaterial));

            TpmHandle transient = LoadTransientAesKey();
            try
            {
                // TPM2_EncryptDecrypt: 1 = encrypt.
                // We generate a random starting IV and store it so decryption can
                // use the exact same IV.  We do NOT store ivOut (the feedback state
                // after encryption) — that is only useful for CFB chaining, not for
                // standalone decryption of this block.
                byte[] ivIn = new byte[16];
                System.Security.Cryptography.RandomNumberGenerator.Fill(ivIn);
                byte[] ciphertext = _tpm.EncryptDecrypt(
                    transient,
                    1,
                    TpmAlgId.Cfb,
                    ivIn,
                    keyMaterial,
                    out _);

                return TPMKeyBlob.Create(
                    ciphertext,
                    ivIn,           // store the starting IV, not the post-encrypt ivOut
                    tpmPublicBlob: _aesPublicBlob,
                    tpmPrivateBlob: [],
                    KeyWrappingEncryptionAlgorithm.AES_256);
            }
            finally
            {
                try { _tpm.FlushContext(transient); } catch { }
            }
        }

        public byte[] Unwrap(TPMKeyBlob wrappedKey)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(TpmKeyWrapper));
            if (wrappedKey is null) throw new ArgumentNullException(nameof(wrappedKey));

            TpmHandle transient = LoadTransientAesKey();
            try
            {
                // TPM2_EncryptDecrypt: 0 = decrypt, supply the stored IV
                byte[] plaintext = _tpm.EncryptDecrypt(
                    transient,
                    0,
                    TpmAlgId.Cfb,
                    wrappedKey.Iv,
                    wrappedKey.Ciphertext,
                    out _);

                return plaintext;
            }
            finally
            {
                try { _tpm.FlushContext(transient); } catch { }
            }
        }

        // ------------------------------------------------------------------ //
        //  Device identity accessor (used by TpmManager)
        // ------------------------------------------------------------------ //

        /// <summary>Returns the stored TpmPublic blob used as the device binding hash input.</summary>
        public byte[] GetAesKeyPublicBlob() => _aesPublicBlob;

        // ------------------------------------------------------------------ //
        //  Key provisioning
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Loads AES key blobs from disk, or creates them for the first time.
        /// The TpmPrivate blob is encrypted by the TPM (wrapped under the storage
        /// primary seed), so storing it on disk is safe - it is only usable on
        /// the specific TPM that created it.
        /// </summary>
        private (byte[] pubBlob, byte[] privBlob) LoadOrCreateAesKeyBlobs()
        {
            string configDir = GetConfigDirectory();
            string pubFile   = Path.Combine(configDir, "tpm_key.pub");
            string privFile  = Path.Combine(configDir, "tpm_key.priv");

            if (File.Exists(pubFile) && File.Exists(privFile))
            {
                byte[] pub  = File.ReadAllBytes(pubFile);
                byte[] priv = File.ReadAllBytes(privFile);

                if (TryVerifyBlobs(pub, priv))
                    return (pub, priv);

                // Blobs invalid (different TPM or re-provisioned) - recreate.
            }

            return CreateAndSaveAesKeyBlobs(configDir, pubFile, privFile);
        }

        private bool TryVerifyBlobs(byte[] pubBlob, byte[] privBlob)
        {
            try
            {
                TpmHandle primary = CreateStoragePrimary();
                try
                {
                    var pub  = Marshaller.FromTpmRepresentation<TpmPublic>(pubBlob);
                    var priv = Marshaller.FromTpmRepresentation<TpmPrivate>(privBlob);
                    TpmHandle transient = _tpm.Load(primary, priv, pub);
                    _tpm.FlushContext(transient);
                    return true;
                }
                finally { _tpm.FlushContext(primary); }
            }
            catch { return false; }
        }

        private (byte[] pubBlob, byte[] privBlob) CreateAndSaveAesKeyBlobs(
            string configDir, string pubFile, string privFile)
        {
            TpmHandle primary = CreateStoragePrimary();
            try
            {
                TpmPrivate aesPriv = _tpm.Create(
                    primary,
                    new SensitiveCreate(),
                    Aes256KeyTemplate,
                    [], [],
                    out TpmPublic aesPub,
                    out _, out _, out _);

                byte[] pubBlob  = aesPub.GetTpmRepresentation();
                byte[] privBlob = aesPriv.GetTpmRepresentation();

                Directory.CreateDirectory(configDir);
                File.WriteAllBytes(pubFile,  pubBlob);
                File.WriteAllBytes(privFile, privBlob);

                return (pubBlob, privBlob);
            }
            finally { _tpm.FlushContext(primary); }
        }

        /// <summary>
        /// Recreates the deterministic storage primary and loads the AES-256 key as
        /// a transient object.  Caller is responsible for calling FlushContext when done.
        /// </summary>
        private TpmHandle LoadTransientAesKey()
        {
            TpmHandle primary = CreateStoragePrimary();
            try
            {
                var pub  = Marshaller.FromTpmRepresentation<TpmPublic>(_aesPublicBlob);
                var priv = Marshaller.FromTpmRepresentation<TpmPrivate>(_aesPrivateBlob);
                return _tpm.Load(primary, priv, pub);
            }
            finally
            {
                // Primary is only needed to authorise Load; flush immediately.
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
            try { _tpm?.Dispose(); } catch { }
            try { _device?.Dispose(); } catch { }
        }
    }
}
