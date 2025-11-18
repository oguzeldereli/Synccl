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

        public LinuxKeychain(ISecureKeyWrapper keyWrapper)
        {
            _keyWrapper = keyWrapper;
        }

        // ---------------------------------------------------------------------------------------
        // PUBLIC API
        // ---------------------------------------------------------------------------------------

        public bool TryGetKey(string account, out byte[] key)
        {
            key = null!;

            var bytes = SecretTool.Read(account);

            var privLength = BitConverter.ToInt32(bytes!, 0);
            var priv = new byte[privLength];
            Array.Copy(bytes!, 4, priv, 0, privLength);

            var pubLength = BitConverter.ToInt32(bytes!, 4 + privLength);
            var pub = new byte[pubLength];
            Array.Copy(bytes!, 8 + privLength, pub, 0, pubLength);

            if (priv == null || pub == null)
                return false;

            key = _keyWrapper.UnwrapKeyWithTPM(priv, pub);

            return true;
        }

        public bool TrySetKey(string account, byte[] key)
        {
            // Store wrapped secret

            var (priv, pub) = _keyWrapper.WrapKeyWithTPM(key);

            var privLengthBytes = BitConverter.GetBytes(priv.Length);
            var pubLengthBytes = BitConverter.GetBytes(pub.Length);

            var bytes = new byte[4 + priv.Length + 4 + pub.Length];
            Array.Copy(privLengthBytes, 0, bytes, 0, 4);
            Array.Copy(priv, 0, bytes, 4, priv.Length);
            Array.Copy(pubLengthBytes, 0, bytes, 4 + priv.Length, 4);
            Array.Copy(pub, 0, bytes, 8 + priv.Length, pub.Length);

            SecretTool.Write(account, bytes);
            return true;
        }

        public bool TryDeleteKey(string account)
        {
            SecretTool.Delete(account);
            return true;
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
    }
}
