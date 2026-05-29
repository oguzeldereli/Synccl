using Synccl.Core.Enums.KeyWrapping;
using Synccl.Core.Interfaces.Security;
using Synccl.Core.Model.Security;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Synccl.Cli.Security
{
    /// <summary>
    /// macOS Secure Enclave key wrapper.
    ///
    /// Key hierarchy:
    ///   Secure Enclave P-256 key  (hardware-bound, non-extractable)
    ///     └─ ECIES-wraps a random per-blob AES-256 session key
    ///           └─ AES-256-GCM encrypts the vault master key material
    ///
    /// TPMKeyBlob field usage:
    ///   Ciphertext    — AES-256-GCM ciphertext (vault master key)
    ///   Iv            — AES-256-GCM nonce (12 bytes) + GCM tag (16 bytes) appended
    ///   TpmPublicBlob — SE-ECIES-wrapped AES session key  (SE.Encrypt output)
    ///   TpmPrivateBlob — SE public key SPKI (device binding / identity)
    /// </summary>
    [SupportedOSPlatform("macos")]
    public sealed class MacSecureEnclaveKeyWrapper : ITPMKeyWrapper
    {
        private const string KeyTag = "com.synccl.vault.sealingkey";
        private const string KeychainService = "synccl";
        private const string KeychainAccount = "vault-session-key";

        // ------------------------------------------------------------------ //
        //  ITPMKeyWrapper
        // ------------------------------------------------------------------ //

        public TPMKeyBlob Wrap(byte[] keyMaterial)
        {
            if (keyMaterial is null || keyMaterial.Length == 0)
                throw new ArgumentException("Key material is required.", nameof(keyMaterial));

            IntPtr priv = SE.GetOrCreatePrivateKey(KeyTag);
            IntPtr pub = SE.CopyPublicKey(priv);

            // 1. Generate a random 32-byte AES-256 session key.
            byte[] sessionKey = new byte[32];
            RandomNumberGenerator.Fill(sessionKey);

            try
            {
                // 2. SE-ECIES-wrap the session key (uses SE private key internally for the device).
                byte[] wrappedSessionKey = SE.Encrypt(pub, sessionKey);

                // 3. AES-256-GCM encrypt the vault key with the session key.
                byte[] nonce = new byte[12];
                RandomNumberGenerator.Fill(nonce);
                byte[] ciphertext = new byte[keyMaterial.Length];
                byte[] tag = new byte[16];

                using var aes = new AesGcm(sessionKey, 16);
                aes.Encrypt(nonce, keyMaterial, ciphertext, tag);

                // Append tag to nonce so we have a single IV blob: [nonce(12)][tag(16)]
                byte[] ivBlob = new byte[28];
                nonce.CopyTo(ivBlob, 0);
                tag.CopyTo(ivBlob, 12);

                // 4. Get SE public key SPKI for device binding.
                byte[] sePublicSpki = SE.ExportPublicKey(pub);

                return TPMKeyBlob.Create(
                    ciphertext,
                    ivBlob,
                    tpmPublicBlob: wrappedSessionKey,
                    tpmPrivateBlob: sePublicSpki,
                    KeyWrappingEncryptionAlgorithm.AES_256);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sessionKey);
            }
        }

        public byte[] Unwrap(TPMKeyBlob wrappedKey)
        {
            if (wrappedKey is null) throw new ArgumentNullException(nameof(wrappedKey));

            IntPtr priv = SE.GetOrCreatePrivateKey(KeyTag);

            // 1. SE-ECIES-unwrap the session key.
            byte[] sessionKey = SE.Decrypt(priv, wrappedKey.TpmPublicBlob);

            try
            {
                // 2. AES-256-GCM decrypt using session key + stored nonce/tag.
                if (wrappedKey.Iv.Length < 28)
                    throw new CryptographicException("Invalid IV blob — expected 28 bytes (nonce+tag).");

                byte[] nonce = wrappedKey.Iv[..12];
                byte[] tag = wrappedKey.Iv[12..28];

                byte[] plaintext = new byte[wrappedKey.Ciphertext.Length];
                using var aes = new AesGcm(sessionKey, 16);
                aes.Decrypt(nonce, wrappedKey.Ciphertext, tag, plaintext);

                return plaintext;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sessionKey);
            }
        }

        // ------------------------------------------------------------------ //
        //  Device identity
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Returns the SHA-256 hash of the Secure Enclave key's SPKI, used as
        /// the stable device identifier (equivalent to EK hash on TPM).
        /// </summary>
        public byte[] GetDeviceIdHash()
        {
            IntPtr priv = SE.GetOrCreatePrivateKey(KeyTag);
            IntPtr pub = SE.CopyPublicKey(priv);
            byte[] spki = SE.ExportPublicKey(pub);
            return SHA256.HashData(spki);
        }

        // ------------------------------------------------------------------ //
        //  Secure Enclave P/Invoke bridge
        // ------------------------------------------------------------------ //

        internal static class SE
        {
            private const string Dylib = "libSecureEnclaveBridge.dylib";

            [DllImport(Dylib, EntryPoint = "CreateSecureEnclaveKey")]
            private static extern IntPtr CreateKey(string tag);

            [DllImport(Dylib, EntryPoint = "LoadSecureEnclaveKey")]
            private static extern IntPtr LoadKey(string tag);

            [DllImport(Dylib, EntryPoint = "CopyPublicKey")]
            private static extern IntPtr CopyPubKey(IntPtr privateKey);

            [DllImport(Dylib, EntryPoint = "SecEncrypt")]
            private static extern IntPtr SecEncrypt(IntPtr pubKey, IntPtr cfData);

            [DllImport(Dylib, EntryPoint = "SecDecrypt")]
            private static extern IntPtr SecDecrypt(IntPtr privKey, IntPtr cfData);

            [DllImport(Dylib, EntryPoint = "DeleteSecureEnclaveKey")]
            private static extern void DeleteKey(string tag);

            [DllImport("/System/Library/Frameworks/Security.framework/Security",
                EntryPoint = "SecKeyCopyExternalRepresentation")]
            private static extern IntPtr SecKeyCopyExternalRepresentation(
                IntPtr key, out IntPtr error);

            // ---- CFData helpers ----

            [DllImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
                EntryPoint = "CFDataCreate")]
            private static extern IntPtr CFDataCreate(IntPtr allocator, byte[] bytes, long length);

            [DllImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
                EntryPoint = "CFDataGetLength")]
            private static extern long CFDataGetLength(IntPtr cfData);

            [DllImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
                EntryPoint = "CFDataGetBytePtr")]
            private static extern IntPtr CFDataGetBytePtr(IntPtr cfData);

            [DllImport("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
                EntryPoint = "CFRelease")]
            private static extern void CFRelease(IntPtr cf);

            // ---- Managed wrappers ----

            public static IntPtr GetOrCreatePrivateKey(string tag)
            {
                IntPtr existing = LoadKey(tag);
                if (existing != IntPtr.Zero) return existing;

                IntPtr created = CreateKey(tag);
                if (created == IntPtr.Zero)
                    throw new CryptographicException("Failed to create Secure Enclave key.");
                return created;
            }

            public static IntPtr CopyPublicKey(IntPtr priv)
            {
                IntPtr pub = CopyPubKey(priv);
                if (pub == IntPtr.Zero)
                    throw new CryptographicException("Failed to copy Secure Enclave public key.");
                return pub;
            }

            public static byte[] Encrypt(IntPtr pubKey, byte[] data)
            {
                IntPtr cfData = ToCFData(data);
                IntPtr enc = SecEncrypt(pubKey, cfData);
                CFRelease(cfData);

                if (enc == IntPtr.Zero)
                    throw new CryptographicException("Secure Enclave ECIES encryption failed.");

                byte[] result = FromCFData(enc);
                CFRelease(enc);
                return result;
            }

            public static byte[] Decrypt(IntPtr privKey, byte[] wrapped)
            {
                IntPtr cfCipher = ToCFData(wrapped);
                IntPtr clear = SecDecrypt(privKey, cfCipher);
                CFRelease(cfCipher);

                if (clear == IntPtr.Zero)
                    throw new CryptographicException("Secure Enclave ECIES decryption failed.");

                byte[] result = FromCFData(clear);
                CFRelease(clear);
                return result;
            }

            public static byte[] ExportPublicKey(IntPtr pubKey)
            {
                IntPtr cfData = SecKeyCopyExternalRepresentation(pubKey, out IntPtr error);
                if (cfData == IntPtr.Zero)
                    throw new CryptographicException("Failed to export Secure Enclave public key.");

                byte[] result = FromCFData(cfData);
                CFRelease(cfData);
                return result;
            }

            private static IntPtr ToCFData(byte[] data)
                => CFDataCreate(IntPtr.Zero, data, data.Length);

            private static byte[] FromCFData(IntPtr cfData)
            {
                long len = CFDataGetLength(cfData);
                IntPtr ptr = CFDataGetBytePtr(cfData);
                byte[] result = new byte[len];
                Marshal.Copy(ptr, result, 0, (int)len);
                return result;
            }
        }
    }
}
