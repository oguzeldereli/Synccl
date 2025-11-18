using Sodium;
using Synccl.Core.Crypto;
using Synccl.Core.Device;
using Synccl.Core.Keys;
using Synccl.Core.Vault;
using System;
using System.Reflection.Metadata.Ecma335;
using System.Text;

namespace Synccl.Core.Vault
{
    public sealed class CurrentDeviceVaultKeyManager
    {
        private readonly DeviceManager _deviceManager;
        private readonly Func<string, (byte[] pub, byte[] priv)> _getDeviceKeys;
        public string VaultKeyAccountBase(string vaultName) => $"synccl:vault:{vaultName}";
        public string NamespaceKeyAccountBase(string vaultName, string nsName) => $"synccl:vault:{vaultName}:namespace:{nsName}";
        public string ItemKeyAccountBase(string vaultName, string nsName, string itemKey) => $"synccl:vault:{vaultName}:namespace:{nsName}:item:{itemKey}";

        public CurrentDeviceVaultKeyManager(DeviceManager deviceManager, Func<string, (byte[] pub, byte[] priv)> getDeviceKeys)
        {
            _deviceManager = deviceManager;
            _getDeviceKeys = getDeviceKeys;
        }

        public byte[] GenerateSymmetricKey() => SodiumCore.GetRandomBytes(32);

        // --------------------------------------------------
        // 1) Vault Key <-> Device Key
        // --------------------------------------------------

        public KeyWrap WrapVKWithDK(string vaultName, byte[] vaultKey, Guid keyId, int version)
        {
            var device = _deviceManager.GetOrCreateCurrentDevice();
            var baseAccount = VaultKeyAccountBase(vaultName);
            var (pub, _) = _getDeviceKeys(baseAccount);
            var keyWrap = VaultKeyWrapper.WrapForDevice(device.DeviceId, pub, vaultKey, keyId, version);

            return keyWrap;
        }

        public byte[] UnwrapVKWithDK(string vaultName, KeyWrap wrap)
        {
            if (wrap.Type != KeyWrap.KeyType.Vault)
                throw new InvalidOperationException("Expected Vault key wrap.");

            var baseAccount = VaultKeyAccountBase(vaultName);
            var (pub, priv) = _getDeviceKeys(baseAccount);
            return Envelope.UnwrapDekWithX25519(wrap.WrappedKey, priv, pub);
        }

        // --------------------------------------------------
        // 2) Namespace Key <-> Vault Key
        // --------------------------------------------------

        public KeyWrap WrapNKWithVKAndDK(string vaultName, string nsName, byte[] namespaceKey, byte[] vaultKey, Guid keyId, int version)
        {
            var device = _deviceManager.GetOrCreateCurrentDevice();
            var aad = Encoding.UTF8.GetBytes("nk-wrap-vk");
            var baseAccount = NamespaceKeyAccountBase(vaultName, nsName);
            var (pub, _) = _getDeviceKeys(baseAccount);

            return VaultKeyWrapper.EncryptAndWrapForDevice(device.DeviceId, pub, vaultKey, namespaceKey, aad, keyId, version);
        }

        public byte[] UnwrapNKWithVK(string vaultName, string nsName, KeyWrap wrap, byte[] vaultKey)
        {
            var baseAccount = NamespaceKeyAccountBase(vaultName, nsName);
            var (pub, priv) = _getDeviceKeys(baseAccount);
            var combined = Envelope.UnwrapDekWithX25519(wrap.WrappedKey, priv, pub);

            var nonce = new byte[24];
            var ct = new byte[combined.Length - 24];
            Buffer.BlockCopy(combined, 0, nonce, 0, 24);
            Buffer.BlockCopy(combined, 24, ct, 0, ct.Length);

            var aad = Encoding.UTF8.GetBytes("nk-wrap-vk");
            return SecretAeadXChaCha20Poly1305.Decrypt(ct, nonce, vaultKey, aad);
        }

        // --------------------------------------------------
        // 3) Item Key <-> Namespace Key
        // --------------------------------------------------

        public KeyWrap WrapIKWithNK(string vaultName, string nsName, string key, byte[] itemKey, byte[] namespaceKey, Guid keyId, int version)
        {
            var aad = Encoding.UTF8.GetBytes("ik-wrap-nk");
            var device = _deviceManager.GetOrCreateCurrentDevice();
            var baseAccount = ItemKeyAccountBase(vaultName, nsName, key);
            var (pub, _) = _getDeviceKeys(baseAccount);

            return VaultKeyWrapper.EncryptAndWrapForDevice(device.DeviceId, pub, namespaceKey, itemKey, aad, keyId, version);

        }
            
        public byte[] UnwrapIKWithNK(string vaultName, string nsName, string key, KeyWrap wrap, byte[] namespaceKey)
        {
            var baseAccount = ItemKeyAccountBase(vaultName, nsName, key);
            var (pub, priv) = _getDeviceKeys(baseAccount);
            var combined = Envelope.UnwrapDekWithX25519(wrap.WrappedKey, priv, pub);

            var nonce = new byte[24];
            var ct = new byte[combined.Length - 24];
            Buffer.BlockCopy(combined, 0, nonce, 0, 24);
            Buffer.BlockCopy(combined, 24, ct, 0, ct.Length);

            var aad = Encoding.UTF8.GetBytes("ik-wrap-nk");
            return SecretAeadXChaCha20Poly1305.Decrypt(ct, nonce, namespaceKey, aad);
        }
    }
}
