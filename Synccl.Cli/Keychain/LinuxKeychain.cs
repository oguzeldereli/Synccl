using Synccl.Core.Keys;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.Versioning;
using System.Text;

namespace Synccl.Cli.Platform
{
    [SupportedOSPlatform("linux")]
    public sealed class LinuxKeychain : IKeychain
    {
        private readonly ISecureKeyWrapper _keyWrapper;
        private readonly string _root;
        private readonly string rsaKeyAccount = "tpm_rsa_key";

        public LinuxKeychain(string root, ISecureKeyWrapper keyWrapper)
        {
            _keyWrapper = keyWrapper;
            _root = root;
        }

        // ---------------------------------------------------------------------------------------
        // PUBLIC API
        // ---------------------------------------------------------------------------------------

        public bool TryGetKey(string account, out byte[] key)
        {
            key = null!;

            var encKey = SecretTool.Read(account);

            if (encKey == null || encKey.Length == 0)
                return false;

            var (privBlob, pubBlob) = RequireRsaKeyBlobs();
            key = _keyWrapper.UnwrapKeyWithTPM(encKey, privBlob, pubBlob);

            return true;
        }

        public bool TrySetKey(string account, byte[] key)
        {
            var (privBlob, pubBlob) = RequireRsaKeyBlobs();
            var encKey = _keyWrapper.WrapKeyWithTPM(key, privBlob, pubBlob);

            SecretTool.Write(account, encKey);
            return true;
        }

        public bool TryDeleteKey(string account)
        {
            SecretTool.Delete(account);
            return true;
        }

        public byte[] GetDevicePublicWrappingKey()
        {
            var (privBlob, pubBlob) = RequireRsaKeyBlobs();
            return _keyWrapper.GetPublicKey(privBlob, pubBlob);
        }

        // ---------------------------------------------------------------------------------------
        // SECRET-TOOL STORAGE HELPERS
        // ---------------------------------------------------------------------------------------

        private static class SecretTool
        {
            public static byte[]? Read(string account)
            {
                var (ok, stdout, _, _) = RunST(
                    $"lookup service synccl account {Esc(account)}");

                if (!ok || string.IsNullOrWhiteSpace(stdout))
                    return null;

                return Convert.FromBase64String(stdout.Trim());
            }

            public static void Write(string account, byte[] wrapped)
            {
                var b64 = Convert.ToBase64String(wrapped);

                RunST(
                    $"store --label=\"synccl\" service synccl account {Esc(account)}",
                    input: b64
                );
            }

            public static void Delete(string account)
            {
                RunST($"clear service synccl account {Esc(account)}", ignoreErrors: true);
            }

            private static (bool ok, string stdout, string stderr, int code) RunST(
                string args, string? input = null, bool ignoreErrors = false)
            {
                var psi = new ProcessStartInfo("secret-tool", args)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    RedirectStandardInput = input != null
                };

                using var p = Process.Start(psi)!;

                if (input != null)
                {
                    p.StandardInput.Write(input);
                    p.StandardInput.Close();
                }

                var stdout = p.StandardOutput.ReadToEnd();
                var stderr = p.StandardError.ReadToEnd();
                p.WaitForExit();

                return (ignoreErrors || p.ExitCode == 0, stdout, stderr, p.ExitCode);
            }

            private static string Esc(string s) =>
                "\"" + s.Replace("\"", "\\\"") + "\"";
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
            byte[] pubBlob, privBlob;
            if (!File.Exists(rsaKeyPath))
            {
                (pubBlob, privBlob) = _keyWrapper.RequireRSAKeyBlobs();
                Directory.CreateDirectory(Path.GetDirectoryName(rsaKeyPath)!);
                using (var fs = new FileStream(rsaKeyPath, FileMode.Open))
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
