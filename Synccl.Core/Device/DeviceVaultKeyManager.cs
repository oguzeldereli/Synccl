using Sodium;
using Synccl.Core.Crypto;
using Synccl.Core.Vault;
using System;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using static Synccl.Core.Vault.KeyWrap;

namespace Synccl.Core.Device
{
    public sealed class DeviceVaultKeyManager
    {
        private readonly DeviceManager _deviceManager;
        private readonly Func<string, (byte[] pub, byte[] priv)> _getDeviceKeys;
        public string VaultKeyAccountBase(string vaultName) => $"synccl:vault:{vaultName}";
        public string NamespaceKeyAccountBase(string vaultName, string nsName) => $"synccl:vault:{vaultName}:namespace:{nsName}";
        public string ItemKeyAccountBase(string vaultName, string nsName, string itemKey) => $"synccl:vault:{vaultName}:namespace:{nsName}:item:{itemKey}";

        public DeviceVaultKeyManager(DeviceManager deviceManager, Func<string, (byte[] pub, byte[] priv)> getDeviceKeys)
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

            return VaultKeyWrapper.WrapForDevice(device.DeviceId, pub, vaultKey, KeyType.Vault, keyId, version);
        }

        public byte[] UnwrapVKWithDK(string vaultName, KeyWrap wrap)
        {
            if (wrap.Type != KeyType.Vault)
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

            return VaultKeyWrapper.EncryptAndWrapForDevice(device.DeviceId, pub, vaultKey, namespaceKey, aad, KeyType.Namespace, keyId, version);
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

            return VaultKeyWrapper.EncryptAndWrapForDevice(device.DeviceId, pub, namespaceKey, itemKey, aad, KeyType.Item, keyId, version);

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

        // --------------------------------------------------
        // Wraps for other devices (used for sharing)
        // --------------------------------------------------

        public KeyWrap WrapVKForDevice(VaultModel vault, Guid deviceId, Guid keyId, int version)
        {
            var currentDevice = _deviceManager.GetOrCreateCurrentDevice();
            var vkWrap = vault.WrappedVaultKeys.FirstOrDefault(w => w.DeviceId == currentDevice.DeviceId && w.Type == KeyType.Vault)
                ?? throw new InvalidOperationException("This device is not authorized to access the vault.");

            var vk = UnwrapVKWithDK(vault.Name, vkWrap);
            if (vk == null)
            {
                throw new InvalidOperationException("Failed to unwrap vault key with current device key.");
            }

            var device = _deviceManager.GetDevice(deviceId);
            if (device == null)
            {
                throw new InvalidOperationException("Target device not found.");
            }

            var pub = _deviceManager.GetDevicePubKey(vault.Name, deviceId);
            if (pub == null || pub.Length == 0)
            {
                throw new InvalidOperationException("Target device does not have a valid vault encryption public key.");
            }

            return VaultKeyWrapper.WrapForDevice(deviceId, pub, vk, KeyType.Vault, keyId, version);
        }

        public KeyWrap WrapNKForDevice(VaultModel vault, string nsName, Guid deviceId, Guid keyId, int version)
        {
            var currentDevice = _deviceManager.GetOrCreateCurrentDevice();
            var vkWrap = vault.WrappedVaultKeys.FirstOrDefault(w => w.DeviceId == currentDevice.DeviceId && w.Type == KeyType.Vault)
                ?? throw new InvalidOperationException("This device is not authorized to access the vault.");

            var vk = UnwrapVKWithDK(vault.Name, vkWrap);
            if (vk == null)
            {
                throw new InvalidOperationException("Failed to unwrap vault key with current device key.");
            }

            var nkWrap = vault.Namespaces.FirstOrDefault(n => n.Name == nsName)
                ?.WrappedNamespaceKeys.FirstOrDefault(w => w.Type == KeyType.Namespace && w.DeviceId == currentDevice.DeviceId)
                ?? throw new InvalidOperationException("This device is not authorized to access the namespace.");

            var nk = UnwrapNKWithVK(vault.Name, nsName, nkWrap, vk);
            if (nk == null)
            {
                throw new InvalidOperationException("Failed to unwrap namespace key with vault key.");
            }

            var device = _deviceManager.GetDevice(deviceId);
            if (device == null)
            {
                throw new InvalidOperationException("Target device not found.");
            }

            var pub = _deviceManager.GetDevicePubKey(vault.Name, nsName, deviceId);
            if (pub == null || pub.Length == 0)
            {
                throw new InvalidOperationException("Target device does not have a valid vault encryption public key.");
            }

            return VaultKeyWrapper.EncryptAndWrapForDevice(deviceId, pub, vk, nk, Encoding.UTF8.GetBytes("nk-wrap-vk"), KeyType.Namespace, keyId, version);
        }

        public KeyWrap WrapIKForDevice(VaultModel vault, string nsName, string itemKey, Guid deviceId, Guid keyId, int version)
        {
            var currentDevice = _deviceManager.GetOrCreateCurrentDevice();
            var vkWrap = vault.WrappedVaultKeys.FirstOrDefault(w => w.DeviceId == currentDevice.DeviceId && w.Type == KeyType.Vault)
                ?? throw new InvalidOperationException("This device is not authorized to access the vault.");

            var vk = UnwrapVKWithDK(vault.Name, vkWrap);
            if (vk == null)
            {
                throw new InvalidOperationException("Failed to unwrap vault key with current device key.");
            }

            var nkWrap = vault.Namespaces.FirstOrDefault(n => n.Name == nsName)
                ?.WrappedNamespaceKeys.FirstOrDefault(w => w.Type == KeyType.Namespace && w.DeviceId == currentDevice.DeviceId)
                ?? throw new InvalidOperationException("This device is not authorized to access the namespace.");

            var nk = UnwrapNKWithVK(vault.Name, nsName, nkWrap, vk);
            if (nk == null)
            {
                throw new InvalidOperationException("Failed to unwrap namespace key with vault key.");
            }

            var ikWrap = vault.Namespaces.FirstOrDefault(n => n.Name == nsName)
                ?.Secrets.FirstOrDefault(i => i.Key == itemKey)
                ?.WrappedItemKeys.FirstOrDefault(w => w.Type == KeyType.Item && w.DeviceId == currentDevice.DeviceId)
                ?? throw new InvalidOperationException("This device is not authorized to access the item.");
            var ik = UnwrapIKWithNK(vault.Name, nsName, itemKey, ikWrap, nk);
            if (ik == null)
            {
                throw new InvalidOperationException("Failed to unwrap item key with namespace key.");
            }

            var device = _deviceManager.GetDevice(deviceId);
            if (device == null)
            {
                throw new InvalidOperationException("Target device not found.");
            }

            var pub = _deviceManager.GetDevicePubKey(vault.Name, nsName, itemKey, deviceId);
            if (pub == null || pub.Length == 0)
            {
                throw new InvalidOperationException("Target device does not have a valid vault encryption public key.");
            }

            return VaultKeyWrapper.EncryptAndWrapForDevice(deviceId, pub, vk, ik, Encoding.UTF8.GetBytes("ik-wrap-nk"), KeyType.Item, keyId, version);
        }
    }
}
