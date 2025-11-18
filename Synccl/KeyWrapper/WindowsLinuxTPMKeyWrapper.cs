using Synccl.Core.Keys;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Tpm2Lib;

namespace Synccl.Cli.KeyWrapper
{
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    public sealed class WindowsLinuxTPMKeyWrapper : ISecureKeyWrapper, IDisposable
    {
        private readonly Tpm2 _tpm;
        private readonly TpmHandle _tpmHandle;
        private readonly Tpm2Device _device;
        private readonly uint _handle;

        private bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        private bool IsLinux => RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

        private static TpmPublic StoragePrimaryTemplate = new TpmPublic(
            TpmAlgId.Sha256,
            ObjectAttr.FixedTPM |
            ObjectAttr.FixedParent |
            ObjectAttr.UserWithAuth |
            ObjectAttr.SensitiveDataOrigin |
            ObjectAttr.Decrypt |
            ObjectAttr.Restricted,
            Array.Empty<byte>(),
            new RsaParms(
                new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb),
                new NullAsymScheme(),
                2048,
                65537
            ),
            new Tpm2bPublicKeyRsa(Array.Empty<byte>())
        );

        private static readonly TpmPublic SealedObjectTemplate = new TpmPublic(
            TpmAlgId.Sha256,
            ObjectAttr.FixedTPM |
            ObjectAttr.FixedParent |
            ObjectAttr.UserWithAuth |
            ObjectAttr.NoDA,
            Array.Empty<byte>(),
            new KeyedhashParms(new NullSchemeKeyedhash()),
            new Tpm2bDigestKeyedhash(Array.Empty<byte>())
        );

        private uint[] GetPersistentHandles()
        {
            uint property = (uint)Ht.Persistent << 24;  // 0x81000000

            _tpm.GetCapability(
                Cap.Handles,
                property,
                256,
                out ICapabilitiesUnion capUnion
            );

            if (capUnion is HandleArray handles)
                return handles.handle.Select(x => x.handle).ToArray();

            return Array.Empty<uint>();
        }

        private uint FindFreePersistentHandle()
        {
            var used = new HashSet<uint>(GetPersistentHandles());

            for (uint h = 0x81000000; h <= 0x8100FFFF; h++)
            {
                if (!used.Contains(h))
                    return h;
            }

            throw new Exception("No free TPM persistent handles available.");
        }

        private TpmHandle GetOrCreateStorageParent(uint handle)
        {
            // =======================================================
            // WINDOWS: no persistent parents allowed by TBS → ephemeral
            // =======================================================
            if (IsWindows)
            {
                return new TpmHandle(0x81000001);
            }

            // =======================================================
            // LINUX: persistent parent supported (original logic)
            // =======================================================
            var tpmHandle = new TpmHandle(handle);

            try
            {
                _tpm.ReadPublic(tpmHandle, out _, out _);
                return tpmHandle;
            }
            catch
            {
                // Not present—create it
            }

            var sensLinux = new SensitiveCreate();

            TpmPublic outPubLinux;
            CreationData creationDataLinux;
            byte[] creationHashLinux;
            TkCreation creationTicketLinux;

            TpmHandle primaryLinux = _tpm.CreatePrimary(
                TpmRh.Owner,
                sensLinux,
                StoragePrimaryTemplate,
                Array.Empty<byte>(),
                Array.Empty<PcrSelection>(),
                out outPubLinux,
                out creationDataLinux,
                out creationHashLinux,
                out creationTicketLinux
            );

            _tpm.EvictControl(TpmRh.Owner, primaryLinux, tpmHandle);
            _tpm.FlushContext(primaryLinux);

            return tpmHandle;
        }

        public WindowsLinuxTPMKeyWrapper(string root)
        {
            if (IsLinux)
                _device = new LinuxTpmDevice();
            else if (IsWindows)
                _device = new TbsDevice();
            else
                throw new PlatformNotSupportedException("TPM Key Wrapper is supported only on Windows and Linux.");

            _device.Connect();
            _tpm = new Tpm2(_device);

            if (IsLinux)
            {
                var handleFile = Path.Combine(root, ".synccl", "tpm_handle");

                if (File.Exists(handleFile))
                {
                    var handleStr = File.ReadAllText(handleFile);
                    if (!uint.TryParse(handleStr, System.Globalization.NumberStyles.HexNumber, null, out _handle))
                        throw new Exception("Invalid TPM handle in file.");
                }
                else
                {
                    _handle = FindFreePersistentHandle();
                    Directory.CreateDirectory(Path.GetDirectoryName(handleFile)!);
                    File.WriteAllText(handleFile, _handle.ToString("X8"));
                }
            }
            else
            {
                _handle = 0; // not used on Windows
            }

            _tpmHandle = GetOrCreateStorageParent(_handle);
        }

        public (byte[] privBlob, byte[] pubBlob) WrapKeyWithTPM(byte[] key)
        {
            var sens = new SensitiveCreate(Array.Empty<byte>(), key);

            TpmPublic outPub;
            CreationData creationData;
            byte[] creationHash;
            TkCreation creationTicket;

            // Create sealed object under the parent (persistent on Linux, ephemeral on Windows)
            TpmPrivate priv = _tpm.Create(
                _tpmHandle,
                sens,
                SealedObjectTemplate,
                Array.Empty<byte>(),
                Array.Empty<PcrSelection>(),
                out outPub,
                out creationData,
                out creationHash,
                out creationTicket
            );

            return (priv.GetTpmRepresentation(), outPub.GetTpmRepresentation());
        }

        public byte[] UnwrapKeyWithTPM(byte[] privBlob, byte[] pubBlob)
        {
            TpmPrivate priv = Marshaller.FromTpmRepresentation<TpmPrivate>(privBlob);
            TpmPublic pub = Marshaller.FromTpmRepresentation<TpmPublic>(pubBlob);

            TpmHandle sealedHandle = _tpm.Load(_tpmHandle, priv, pub);
            byte[] unsealed = _tpm.Unseal(sealedHandle);

            _tpm.FlushContext(sealedHandle);

            return unsealed;
        }

        public void DeleteStorageParent()
        {
            if (IsWindows)
                return; // nothing to delete

            var persistent = _tpmHandle;

            try
            {
                _tpm.ReadPublic(persistent, out _, out _);
            }
            catch
            {
                return;
            }

            _tpm.EvictControl(TpmRh.Owner, persistent, persistent);
        }

        public void Dispose()
        {
            if (IsWindows)
            {
                try { _tpm.FlushContext(_tpmHandle); } catch { }
            }

            _tpm?.Dispose();
            _device?.Dispose();
        }
    }
}
