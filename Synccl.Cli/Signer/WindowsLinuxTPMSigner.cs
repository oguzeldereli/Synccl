using Synccl.Cli.KeyWrapper;
using Synccl.Core.Security;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Tpm2Lib;

namespace Synccl.Cli.Signer
{
    [SupportedOSPlatform("windows")]
    [SupportedOSPlatform("linux")]
    public sealed class WindowsLinuxTPMSigner : ISecureSigner, IDisposable
    {
        private readonly Tpm2 _tpm;
        private readonly TpmHandle _tpmHandle;
        private readonly Tpm2Device _device;
        private readonly uint _handle;
        private TpmPublic? _pubSignKey;
        private TpmPrivate? _privSignKey;
        private readonly string _keyPath;

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

        private static readonly TpmPublic _signingTemplate = new TpmPublic(
            TpmAlgId.Sha256,
            ObjectAttr.FixedTPM |
            ObjectAttr.FixedParent |
            ObjectAttr.UserWithAuth |
            ObjectAttr.SensitiveDataOrigin |
            ObjectAttr.Sign,
            [],
            new EccParms(
                new SymDefObject(TpmAlgId.Null, 0, TpmAlgId.Null),
                new SigSchemeEcdsa(TpmAlgId.Sha256),  // ECDSA SHA-256
                EccCurve.TpmEccNistP256,
                new NullKdfScheme()
            ),
            new EccPoint()
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

        public WindowsLinuxTPMSigner(string root)
        {
            if (IsLinux)
                _device = new LinuxTpmDevice();
            else if (IsWindows)
                _device = new TbsDevice();
            else
                throw new PlatformNotSupportedException("TPM Key Wrapper is supported only on Windows and Linux.");

            _device.Connect();
            _tpm = new Tpm2(_device);

            _keyPath = Path.Combine(root, ".synccl", "tpm_signing_key"); 
            Directory.CreateDirectory(Path.GetDirectoryName(_keyPath)!);

            if (IsLinux)
            {
                var handleFile = Path.Combine(root, ".synccl", "tpm_sign_handle");

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

        private TpmHandle GetOrCreateStorageParent(uint handle)
        {
            // =======================================================
            // WINDOWS: no persistent parents allowed by TBS → ephemeral
            // =======================================================
            if (IsWindows)
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

        public byte[] GetDevicePublicKey()
        {
            if (_pubSignKey == null || _privSignKey == null)
            {
                if (File.Exists(_keyPath))
                {
                    using var fs = File.OpenRead(_keyPath);
                    var br = new BinaryReader(fs);
                    int pubLen = br.ReadInt32();
                    var pubBytes = br.ReadBytes(pubLen);
                    _pubSignKey = Marshaller.FromTpmRepresentation<TpmPublic>(pubBytes);
                    int privLen = br.ReadInt32();
                    var privBytes = br.ReadBytes(privLen);
                    _privSignKey = Marshaller.FromTpmRepresentation<TpmPrivate>(privBytes);
                }
                else
                {
                    _privSignKey = _tpm.Create(
                        _tpmHandle,
                        new SensitiveCreate(),
                        _signingTemplate,
                        Array.Empty<byte>(),
                        Array.Empty<PcrSelection>(),
                        out _pubSignKey,
                        out CreationData _,
                        out _,
                        out _
                    );

                    using var fs = File.Create(_keyPath);
                    var bw = new BinaryWriter(fs);
                    bw.Write(_pubSignKey.GetTpmRepresentation().Length);
                    bw.Write(_pubSignKey.GetTpmRepresentation());
                    bw.Write(_privSignKey.GetTpmRepresentation().Length);
                    bw.Write(_privSignKey.GetTpmRepresentation());
                }
            }

            var eccPoint = (EccPoint)_pubSignKey.unique;
            using var ecdsa = ECDsa.Create(new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = { X = eccPoint.x, Y = eccPoint.y }
            });

            return ecdsa.ExportSubjectPublicKeyInfo();
        }


        public byte[] SignData(byte[] data)
        {
            if (_pubSignKey == null || _privSignKey == null)
                GetDevicePublicKey();
            var key = _tpm.Load(_tpmHandle, _privSignKey, _pubSignKey);

            byte[] digest = SHA256.HashData(data);

            var sig = _tpm.Sign(key, digest, new SigSchemeEcdsa(TpmAlgId.Sha256), null);
            
            _tpm.FlushContext(key);

            var s = (SignatureEcdsa)sig; 
            var r = FixAndPad(s.signatureR);
            var sVal = FixAndPad(s.signatureS);

            var signature = new byte[64];
            Buffer.BlockCopy(r, 0, signature, 0, 32);
            Buffer.BlockCopy(sVal, 0, signature, 32, 32);
            return signature;

            byte[] FixAndPad(byte[] v)
            {
                int keySizeBytes = 32;
                var fixedV = v.Length > keySizeBytes
                    ? v.Skip(v.Length - keySizeBytes).ToArray()
                    : v;

                var padded = new byte[keySizeBytes];
                Buffer.BlockCopy(fixedV, 0, padded, keySizeBytes - fixedV.Length, fixedV.Length);
                return padded;
            }
        }

        public bool VerifyP256(byte[] data, byte[] signature, byte[] publicKey)
        {
            using (ECDsa ecdsa = ECDsa.Create())
            {
                ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);
                return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256);
            }
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

        public void DeleteSigningKey()
        {
            if (File.Exists(_keyPath))
            {
                File.Delete(_keyPath);
            }
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
