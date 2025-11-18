using Sodium;
using Synccl.Core.Keys;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

            var lines = File.ReadAllBytes(path);
            if (lines.Length == 0)
                return false;

            byte[] privBlob, pubBlob;

            using (var fs = new FileStream(path, FileMode.Open))
            using (var sr = new BinaryReader(fs))
            {
                int len = sr.ReadInt32();
                privBlob = sr.ReadBytes(len);

                len = sr.ReadInt32();
                pubBlob = sr.ReadBytes(len);
            }

            var unprotectedPriv = ProtectedData.Unprotect(privBlob,
                optionalEntropy: null, scope: DataProtectionScope.CurrentUser);

            var unprotectedPub = ProtectedData.Unprotect(pubBlob,
                optionalEntropy: null, scope: DataProtectionScope.CurrentUser);

            var unwrapped = _keyWrapper.UnwrapKeyWithTPM(unprotectedPriv, unprotectedPub);

            key = unwrapped;
            return true;
        }

        public bool TrySetKey(string account, byte[] key)
        {
            var (privBlob, pubBlob) = _keyWrapper.WrapKeyWithTPM(key);

            var protectedBytesPriv = ProtectedData.Protect(privBlob,
                optionalEntropy: null, scope: DataProtectionScope.CurrentUser);
            var protectedBytesPub = ProtectedData.Protect(pubBlob,
                optionalEntropy: null, scope: DataProtectionScope.CurrentUser);

            var file = GetPath(_root, account);

            Directory.CreateDirectory(Path.GetDirectoryName(file)!);

            using (var fs = new FileStream(file, FileMode.Create, FileAccess.Write))
            using (var bw = new BinaryWriter(fs))
            {
                var len = protectedBytesPriv.Length;
                bw.Write(len);
                bw.Write(protectedBytesPriv);

                len = protectedBytesPub.Length;
                bw.Write(len);
                bw.Write(protectedBytesPub);
            }
            
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

        private static string GetPath(string root, string account)
        {
            var baseDir = Path.Combine(root, ".synccl", "keys");
            var safe = Convert.ToBase64String(Encoding.UTF8.GetBytes(account))
                           .Replace('/', '_')
                           .Replace('+', '-');
            return Path.Combine(baseDir, $"{safe}.bin");
        }
    }
}