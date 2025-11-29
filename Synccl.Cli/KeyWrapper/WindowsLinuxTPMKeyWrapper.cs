using Synccl.Core.Keys;
using System.Reflection.Metadata;
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
        private readonly Tpm2Device _device;
        private readonly TpmHandle parent;
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

        private static readonly TpmPublic RsaDecryptionTemplate =
            new TpmPublic(
                TpmAlgId.Sha256,
                ObjectAttr.Decrypt |
                ObjectAttr.UserWithAuth |
                ObjectAttr.SensitiveDataOrigin |
                ObjectAttr.FixedTPM |
                ObjectAttr.FixedParent,
                Array.Empty<byte>(),
                new RsaParms(
                    new SymDefObject(TpmAlgId.Null, 0, TpmAlgId.Null),
                    new NullAsymScheme(),
                    2048,
                    65537
                ),
                new Tpm2bPublicKeyRsa(new byte[0])
            );

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

            uint handle;
            if (IsLinux)
            {
                var handleFile = Path.Combine(root, ".synccl", "tpm_handle");

                if (File.Exists(handleFile))
                {
                    var handleStr = File.ReadAllText(handleFile);
                    if (!uint.TryParse(handleStr, System.Globalization.NumberStyles.HexNumber, null, out handle))
                        throw new Exception("Invalid TPM handle in file.");
                }
                else
                {
                    handle = FindFreePersistentHandle();
                    Directory.CreateDirectory(Path.GetDirectoryName(handleFile)!);
                    File.WriteAllText(handleFile, handle.ToString("X8"));
                }
            }
            else
            {
                handle = 0; // Not used on Windows
            }

            parent = GetOrCreateStorageParent(handle);
        }

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
            if (handle == 0)
            {
                TpmPublic pub;
                CreationData cd;
                byte[] ch;
                TkCreation tk;

                var primary = _tpm.CreatePrimary(
                    TpmRh.Owner,
                    new SensitiveCreate(),
                    StoragePrimaryTemplate,
                    Array.Empty<byte>(),
                    Array.Empty<PcrSelection>(),
                    out pub,
                    out cd,
                    out ch,
                    out tk
                );

                return primary;
            }

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

        public (byte[] privBlob, byte[] pubBlob) RequireRSAKeyBlobs()
        {
            TpmPrivate priv = null!;
            TpmPublic pub = null!;
            priv = _tpm.Create(
                parent,
                new SensitiveCreate(),
                RsaDecryptionTemplate,
                Array.Empty<byte>(),
                Array.Empty<PcrSelection>(),
                out pub,
                out _,
                out _,
                out _
            );
            byte[] privBlob = priv.GetTpmRepresentation();
            byte[] pubBlob = pub.GetTpmRepresentation();
            return (privBlob, pubBlob);
        }

        public byte[] WrapKeyWithTPM(byte[] key, byte[] privBlob, byte[] pubBlob)
        {
            if (privBlob == null || pubBlob == null)
                throw new ArgumentException("Private and public blobs must be provided for wrapping.");
            TpmPrivate priv;
            TpmPublic pub;

            var inPriv = Marshaller.FromTpmRepresentation<TpmPrivate>(privBlob);
            var inPub = Marshaller.FromTpmRepresentation<TpmPublic>(pubBlob);

            pub = inPub;
            priv = inPriv;

            var rsaPub = (Tpm2bPublicKeyRsa)pub.unique;
            var parms = (RsaParms)pub.parameters;

            using RSA rsa = RSA.Create(new RSAParameters
            {
                Modulus = rsaPub.buffer,
                Exponent = BitConverter.GetBytes(parms.exponent).Reverse().ToArray()
            });

            byte[] wrapped = rsa.Encrypt(key, RSAEncryptionPadding.OaepSHA256);

            return wrapped;
        }

        public byte[] UnwrapKeyWithTPM(byte[] wrappedKey, byte[] privBlob, byte[] pubBlob)
        {
            if (privBlob == null || pubBlob == null)
                throw new ArgumentException("Private and public blobs must be provided for unwrapping.");
            var inPriv = Marshaller.FromTpmRepresentation<TpmPrivate>(privBlob);
            var inPub = Marshaller.FromTpmRepresentation<TpmPublic>(pubBlob);
            TpmHandle loadedHandle = _tpm.Load(
                parent,
                inPriv,
                inPub
            );

            byte[] decrypted = _tpm.RsaDecrypt(
                loadedHandle,
                wrappedKey,
                new SchemeOaep(TpmAlgId.Sha256),
                Array.Empty<byte>()
            );

            _tpm.FlushContext(loadedHandle);
            return decrypted;
        }

        public byte[] GetPublicKey(byte[] privBlob, byte[] pubBlob)
        {
            if (privBlob == null || pubBlob == null)
                throw new ArgumentException("Private and public blobs must be provided for getting public key.");
            var inPriv = Marshaller.FromTpmRepresentation<TpmPrivate>(privBlob);
            var inPub = Marshaller.FromTpmRepresentation<TpmPublic>(pubBlob);
            TpmHandle loadedHandle = _tpm.Load(
                parent,
                inPriv,
                inPub
            );
            TpmPublic pubKey = _tpm.ReadPublic(loadedHandle, out _, out _);
            _tpm.FlushContext(loadedHandle);
            if (pubKey.parameters is RsaParms rsaParms &&
                pubKey.unique is Tpm2bPublicKeyRsa rsaKey)
            {
                using RSA rsa = RSA.Create();
                RSAParameters rsaParams = new RSAParameters
                {
                    Modulus = rsaKey.buffer,
                    Exponent = BitConverter.GetBytes(rsaParms.exponent)
                };
                rsa.ImportParameters(rsaParams);
                return rsa.ExportSubjectPublicKeyInfo();
            }
            else
            {
                throw new Exception("Unexpected public key format.");
            }
        }

        public void Dispose()
        {
            if (IsWindows)
            {
                try { _tpm.FlushContext(parent); } catch { }
            }

            _tpm?.Dispose();
            _device?.Dispose();
        }
    }
}
