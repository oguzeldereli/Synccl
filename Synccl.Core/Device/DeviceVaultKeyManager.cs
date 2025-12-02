using Sodium;
using Synccl.Core.Crypto;
using Synccl.Core.Vault;
using Synccl.Core.VaultCrypto;
using System;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using System.Xml.Linq;
using static Synccl.Core.Vault.KeyWrap;

namespace Synccl.Core.Device
{
    public sealed class DeviceVaultKeyManager
    {
        private readonly DeviceManager _deviceManager;

        public DeviceVaultKeyManager(DeviceManager deviceManager)
        {
            _deviceManager = deviceManager;
        }

        public byte[] GenerateSymmetricKey() => SodiumCore.GetRandomBytes(32);

        // --------------------------------------------------
        // 1) Vault Key <-> Device Key
        // --------------------------------------------------

        public KeyWrap WrapVKWithDK(byte[] vaultKey, Guid keyId, int version)
        {
            var device = _deviceManager.GetOrCreateCurrentDevice(vaultKey);
            var (pub, _) = _deviceManager.GetOrCreateDeviceVaultKEK();

            return VaultCryptoEngine.WrapForDevice(device.DeviceId, pub, vaultKey, KeyType.Vault, keyId, version);
        }

        public byte[] UnwrapVKWithDK(KeyWrap wrap)
        {
            if (wrap.Type != KeyType.Vault)
                throw new InvalidOperationException("Expected Vault key wrap.");

            byte[] pub, priv;
            if (wrap.DevicePrivateKeyForWrap != null)
            {
                (pub, priv) = (wrap.DevicePublicKeyForWrap, wrap.DevicePrivateKeyForWrap);
            }
            else
            {
                (pub, priv) = _deviceManager.GetDeviceVaultKEK();
            }

            return Envelope.UnwrapDekWithX25519(wrap.WrappedKey, priv, pub);
        }

        // --------------------------------------------------
        // 2) Namespace Key <-> Vault Key
        // --------------------------------------------------

        public KeyWrap WrapNKWithVKAndDK(string nsName, byte[] namespaceKey, byte[] vaultKey, Guid keyId, int version)
        {
            var device = _deviceManager.GetOrCreateCurrentDevice(vaultKey);
            var aad = Encoding.UTF8.GetBytes("nk-wrap-vk");
            var (pub, _) = _deviceManager.GetOrCreateDeviceNamespaceKEK(nsName);

            return VaultCryptoEngine.EncryptAndWrapForDevice(device.DeviceId, pub, vaultKey, namespaceKey, aad, KeyType.Namespace, keyId, version);
        }

        public byte[] UnwrapNKWithVK(string nsName, KeyWrap wrap, byte[] vaultKey)
        {
            byte[] pub, priv;
            if (wrap.DevicePrivateKeyForWrap != null)
            {
                (pub, priv) = (wrap.DevicePublicKeyForWrap, wrap.DevicePrivateKeyForWrap);
            }
            else
            {
                (pub, priv) = _deviceManager.GetDeviceNamespaceKEK(nsName);
            }
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

        public KeyWrap WrapIKWithNK(string nsName, string key, byte[] itemKey, byte[] namespaceKey, byte[] vaultKey, Guid keyId, int version)
        {
            var aad = Encoding.UTF8.GetBytes("ik-wrap-nk");
            var device = _deviceManager.GetOrCreateCurrentDevice(vaultKey);
            var (pub, _) = _deviceManager.GetOrCreateDeviceItemKEK(nsName, key);

            return VaultCryptoEngine.EncryptAndWrapForDevice(device.DeviceId, pub, namespaceKey, itemKey, aad, KeyType.Item, keyId, version);

        }
            
        public byte[] UnwrapIKWithNK(string nsName, string key, KeyWrap wrap, byte[] namespaceKey)
        {
            byte[] pub, priv;
            if (wrap.DevicePrivateKeyForWrap != null)
            {
                (pub, priv) = (wrap.DevicePublicKeyForWrap, wrap.DevicePrivateKeyForWrap);
            }
            else
            {
                (pub, priv) = _deviceManager.GetDeviceItemKEK(nsName, key);
            }

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
            var currentDeviceId = _deviceManager.GetCurrentDeviceId();
            var vkWrap = vault.WrappedVaultKeys.FirstOrDefault(w => w.DeviceId == currentDeviceId && w.Type == KeyType.Vault)
                ?? throw new InvalidOperationException("This device is not authorized to access the vault.");

            var vk = UnwrapVKWithDK(vkWrap);
            if (vk == null)
            {
                throw new InvalidOperationException("Failed to unwrap vault key with current device key.");
            }

            var device = _deviceManager.GetDevice(deviceId, vk);
            if (device == null)
            {
                throw new InvalidOperationException("Target device not found.");
            }

            var pub = _deviceManager.GetDeviceVaultPubKey(vk, deviceId);
            if (pub == null || pub.Length == 0)
            {
                throw new InvalidOperationException("Target device does not have a valid vault encryption public key.");
            }

            return VaultCryptoEngine.WrapForDevice(deviceId, pub, vk, KeyType.Vault, keyId, version);
        }

        public KeyWrap WrapNKForDevice(VaultModel vault, string nsName, Guid deviceId, Guid keyId, int version)
        {
            var currentDeviceId = _deviceManager.GetCurrentDeviceId();
            var vkWrap = vault.WrappedVaultKeys.FirstOrDefault(w => w.DeviceId == currentDeviceId && w.Type == KeyType.Vault)
                ?? throw new InvalidOperationException("This device is not authorized to access the vault.");

            var vk = UnwrapVKWithDK(vkWrap);
            if (vk == null)
            {
                throw new InvalidOperationException("Failed to unwrap vault key with current device key.");
            }

            var nkWrap = vault.Namespaces.FirstOrDefault(n => n.Name == nsName)
                ?.WrappedNamespaceKeys.FirstOrDefault(w => w.Type == KeyType.Namespace && w.DeviceId == currentDeviceId)
                ?? throw new InvalidOperationException("This device is not authorized to access the namespace.");

            var nk = UnwrapNKWithVK(nsName, nkWrap, vk);
            if (nk == null)
            {
                throw new InvalidOperationException("Failed to unwrap namespace key with vault key.");
            }

            var device = _deviceManager.GetDevice(deviceId, vk);
            if (device == null)
            {
                throw new InvalidOperationException("Target device not found.");
            }

            var pub = _deviceManager.GetDeviceNamespacePubKey(vk, nsName, deviceId);
            if (pub == null || pub.Length == 0)
            {
                throw new InvalidOperationException("Target device does not have a valid vault encryption public key.");
            }

            return VaultCryptoEngine.EncryptAndWrapForDevice(deviceId, pub, vk, nk, Encoding.UTF8.GetBytes("nk-wrap-vk"), KeyType.Namespace, keyId, version);
        }

        public KeyWrap WrapIKForDevice(VaultModel vault, string nsName, string itemKey, Guid deviceId, Guid keyId, int version)
        {
            var currentDeviceId = _deviceManager.GetCurrentDeviceId();
            var vkWrap = vault.WrappedVaultKeys.FirstOrDefault(w => w.DeviceId == currentDeviceId && w.Type == KeyType.Vault)
                ?? throw new InvalidOperationException("This device is not authorized to access the vault.");

            var vk = UnwrapVKWithDK(vkWrap);
            if (vk == null)
            {
                throw new InvalidOperationException("Failed to unwrap vault key with current device key.");
            }

            var nkWrap = vault.Namespaces.FirstOrDefault(n => n.Name == nsName)
                ?.WrappedNamespaceKeys.FirstOrDefault(w => w.Type == KeyType.Namespace && w.DeviceId == currentDeviceId)
                ?? throw new InvalidOperationException("This device is not authorized to access the namespace.");

            var nk = UnwrapNKWithVK(nsName, nkWrap, vk);
            if (nk == null)
            {
                throw new InvalidOperationException("Failed to unwrap namespace key with vault key.");
            }

            var ikWrap = vault.Namespaces.FirstOrDefault(n => n.Name == nsName)
                ?.Secrets.FirstOrDefault(i => i.Key == itemKey)
                ?.WrappedItemKeys.FirstOrDefault(w => w.Type == KeyType.Item && w.DeviceId == currentDeviceId)
                ?? throw new InvalidOperationException("This device is not authorized to access the item.");
            var ik = UnwrapIKWithNK(nsName, itemKey, ikWrap, nk);
            if (ik == null)
            {
                throw new InvalidOperationException("Failed to unwrap item key with namespace key.");
            }

            var device = _deviceManager.GetDevice(deviceId, vk);
            if (device == null)
            {
                throw new InvalidOperationException("Target device not found.");
            }

            var pub = _deviceManager.GetDeviceItemPubKey(vk, nsName, itemKey, deviceId);
            if (pub == null || pub.Length == 0)
            {
                throw new InvalidOperationException("Target device does not have a valid vault encryption public key.");
            }

            return VaultCryptoEngine.EncryptAndWrapForDevice(deviceId, pub, vk, ik, Encoding.UTF8.GetBytes("ik-wrap-nk"), KeyType.Item, keyId, version);
        }
    }
}
