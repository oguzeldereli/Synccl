using Sodium;
using Synccl.Core.Keys;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
namespace Synccl.Cli.Platform
{
    [SupportedOSPlatform("windows")]
    public sealed class WindowsKeychain : IKeychain
    {
        private readonly ISecureKeyWrapper _keyWrapper;
        private readonly string _root;
        private readonly string rsaKeyAccount = "tpm_rsa_key";

        public WindowsKeychain(string root, ISecureKeyWrapper keyWrapper)
        {
            _keyWrapper = keyWrapper;
            _root = root;
        }

        public bool TryGetKey(string account, out byte[] key)
        {
            key = null!;
            var path = GetPath(_root, account);
            if (!File.Exists(path))
                return false;

            var encProtectedKey = File.ReadAllBytes(path);
            if (encProtectedKey.Length == 0)
                return false;

            var encUnprotectedKey = ProtectedData.Unprotect(encProtectedKey,
                optionalEntropy: null, scope: DataProtectionScope.CurrentUser);

            var (privBlob, pubBlob) = RequireRsaKeyBlobs();
            key = _keyWrapper.UnwrapKeyWithTPM(encUnprotectedKey, privBlob, pubBlob);

            return true;
        }

        public bool TrySetKey(string account, byte[] key)
        {
            var (privBlob, pubBlob) = RequireRsaKeyBlobs();
            var encKey = _keyWrapper.WrapKeyWithTPM(key, privBlob, pubBlob);
            var encProtectedKey = ProtectedData.Protect(encKey,
                optionalEntropy: null, scope: DataProtectionScope.CurrentUser);

            var file = GetPath(_root, account);
            Directory.CreateDirectory(Path.GetDirectoryName(file)!);
            File.WriteAllBytes(file, encProtectedKey);
            return true;
        }

        public bool TryDeleteKey(string account)
        {
            try
            {
                var path = GetPath(_root, account);
                if (File.Exists(path))
                    File.Delete(path);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public byte[] GetDevicePublicWrappingKey()
        {
            var (privBlob, pubBlob) = RequireRsaKeyBlobs();
            return _keyWrapper.GetPublicKey(privBlob, pubBlob);
        }

        private static string GetPath(string root, string account)
        {
            var baseDir = Path.Combine(root, ".synccl", "Keys");
            var safe = Convert.ToBase64String(Encoding.UTF8.GetBytes(account))
                           .Replace('/', '_')
                           .Replace('+', '-');
            return Path.Combine(baseDir, $"{safe}.bin");
        }

        private (byte[] privBlob, byte[] pubBlob) RequireRsaKeyBlobs()
        {
            var rsaKeyPath = GetPath(_root, rsaKeyAccount);
            byte[] privBlob, pubBlob;
            if (!File.Exists(rsaKeyPath))
            {
                (privBlob, pubBlob) = _keyWrapper.RequireRSAKeyBlobs();
                Directory.CreateDirectory(Path.GetDirectoryName(rsaKeyPath)!);
                using (var fs = new FileStream(rsaKeyPath, FileMode.OpenOrCreate))
                using (var sr = new BinaryWriter(fs))
                {
                    sr.Write(privBlob.Length);
                    sr.Write(privBlob);
                    sr.Write(pubBlob.Length);
                    sr.Write(pubBlob);
                }
            }
            else
            {

                using (var fs = new FileStream(rsaKeyPath, FileMode.Open))
                using (var sr = new BinaryReader(fs))
                {
                    var len = sr.ReadInt32();
                    privBlob = sr.ReadBytes(len);
                    len = sr.ReadInt32();
                    pubBlob = sr.ReadBytes(len);
                }
            }

            return (privBlob, pubBlob);
        }
    }
}