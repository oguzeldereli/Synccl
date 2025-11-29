using Synccl.Core.Keys;
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Synccl.Cli.Platform
{
    [SupportedOSPlatform("macos")]
    public sealed class MacKeychain : IKeychain
    {
        private const string Tag = "synccl.hardwarekey";
        private const string Service = "synccl";

        public bool TryGetKey(string account, out byte[] key)
        {
            key = null!;

            byte[]? wrapped = KeychainSecrets.Read(Service, account);
            if (wrapped == null)
                return false;

            IntPtr priv = SE.GetOrCreatePrivateKey(Tag);
            key = SE.Decrypt(priv, wrapped);
            return true;
        }

        public bool TrySetKey(string account, byte[] key)
        {
            IntPtr priv = SE.GetOrCreatePrivateKey(Tag);
            IntPtr pub = SE.CopyPubKey(priv);

            byte[] wrapped = SE.Encrypt(pub, key);
            KeychainSecrets.Write(Service, account, wrapped);
            return true;
        }

        public bool TryDeleteKey(string account)
        {
            KeychainSecrets.Delete(Service, account);
            SE.DeleteKey(Tag);
            return true;
        }

        public byte[] GetDevicePublicWrappingKey()
        {
            IntPtr priv = SE.GetOrCreatePrivateKey(Tag);
            IntPtr pub = SE.CopyPubKey(priv);
            byte[] spki = SE.ExportPublicKey(pub);

            return spki;
        }

        // ----------------------------------------------------------------------
        // Secure Enclave + P/Invoke bridge
        // ----------------------------------------------------------------------

        private static class SE
        {
            private const string Dylib = "libSecureEnclaveBridge.dylib";

            [DllImport(Dylib)]
            private static extern IntPtr CreateSecureEnclaveKey(string tag);

            [DllImport(Dylib)]
            private static extern IntPtr LoadSecureEnclaveKey(string tag);

            [DllImport(Dylib)]
            private static extern IntPtr CopyPublicKey(IntPtr privateKey);

            [DllImport(Dylib)]
            private static extern IntPtr SecEncrypt(IntPtr pubKey, IntPtr data);

            [DllImport(Dylib)]
            private static extern IntPtr SecDecrypt(IntPtr privKey, IntPtr cipher);

            [DllImport(Dylib)]
            private static extern void DeleteSecureEnclaveKey(string tag);

            [DllImport("/System/Library/Frameworks/Security.framework/Security")]
            private static extern IntPtr SecKeyCopyExternalRepresentation(
                IntPtr key,
                out IntPtr error
            );

            public static IntPtr GetOrCreatePrivateKey(string tag)
            {
                IntPtr existing = LoadSecureEnclaveKey(tag);
                if (existing != IntPtr.Zero)
                    return existing;

                IntPtr created = CreateSecureEnclaveKey(tag);
                if (created == IntPtr.Zero)
                    throw new Exception("Failed to create Secure Enclave key");

                return created;
            }

            public static IntPtr CopyPubKey(IntPtr priv)
            {
                IntPtr pub = CopyPublicKey(priv);
                if (pub == IntPtr.Zero)
                    throw new Exception("Failed to copy public key");
                return pub;
            }

            public static byte[] Encrypt(IntPtr pubKey, byte[] data)
            {
                IntPtr cfData = CF.ToCFData(data);
                IntPtr enc = SecEncrypt(pubKey, cfData);
                CF.Release(cfData);

                if (enc == IntPtr.Zero)
                    throw new Exception("Secure Enclave encryption failed");

                byte[] result = CF.FromCFData(enc);
                CF.Release(enc);
                return result;
            }

            public static byte[] Decrypt(IntPtr privKey, byte[] wrapped)
            {
                IntPtr cfCipher = CF.ToCFData(wrapped);
                IntPtr clear = SecDecrypt(privKey, cfCipher);
                CF.Release(cfCipher);

                if (clear == IntPtr.Zero)
                    throw new Exception("Secure Enclave decryption failed");

                byte[] result = CF.FromCFData(clear);
                CF.Release(clear);
                return result;
            }

            public static byte[] ExportPublicKey(IntPtr pubKey)
            {
                IntPtr error;

                IntPtr cfData = SecKeyCopyExternalRepresentation(pubKey, out error);

                if (cfData == IntPtr.Zero)
                    throw new Exception("Failed to export public key via SecKeyCopyExternalRepresentation");

                byte[] result = CF.FromCFData(cfData);
                CF.Release(cfData);

                return result;
            }


            public static void DeleteKey(string tag)
            {
                DeleteSecureEnclaveKey(tag);
            }
        }

        // ----------------------------------------------------------------------
        // CFData helpers
        // ----------------------------------------------------------------------

        private static class CF
        {
            [DllImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")]
            private static extern void CFRelease(IntPtr cf);

            [DllImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")]
            private static extern IntPtr CFDataCreate(IntPtr allocator, byte[] bytes, long length);

            [DllImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")]
            private static extern long CFDataGetLength(IntPtr cfData);

            [DllImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")]
            private static extern IntPtr CFDataGetBytePtr(IntPtr cfData);

            public static IntPtr ToCFData(byte[] data) =>
                CFDataCreate(IntPtr.Zero, data, data.Length);

            public static byte[] FromCFData(IntPtr cfData)
            {
                long len = CFDataGetLength(cfData);
                IntPtr ptr = CFDataGetBytePtr(cfData);

                var result = new byte[len];
                Marshal.Copy(ptr, result, 0, (int)len);
                return result;
            }

            public static void Release(IntPtr cf) => CFRelease(cf);
        }

        // ----------------------------------------------------------------------
        // Keychain password storage (secret wrapper storage only)
        // ----------------------------------------------------------------------

        private static class KeychainSecrets
        {
            public static void Write(string service, string account, byte[] wrapped)
            {
                string b64 = Convert.ToBase64String(wrapped);
                Run($"delete-generic-password -s \"{service}\" -a \"{account}\"", true);
                Run($"add-generic-password -s \"{service}\" -a \"{account}\" -w \"{b64}\" -U");
            }

            public static byte[]? Read(string service, string account)
            {
                var (ok, outp, _) = Run($"find-generic-password -s \"{service}\" -a \"{account}\" -w");
                if (!ok || string.IsNullOrWhiteSpace(outp))
                    return null;

                return Convert.FromBase64String(outp.Trim());
            }

            public static void Delete(string service, string account)
            {
                Run($"delete-generic-password -s \"{service}\" -a \"{account}\"", true);
            }

            private static (bool ok, string stdout, string stderr) Run(string args, bool ignoreErrors = false)
            {
                var psi = new ProcessStartInfo("security", args)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using var p = Process.Start(psi)!;
                string stdout = p.StandardOutput.ReadToEnd();
                string stderr = p.StandardError.ReadToEnd();
                p.WaitForExit();

                return (ignoreErrors || p.ExitCode == 0, stdout, stderr);
            }
        }
    }
}
