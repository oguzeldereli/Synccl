using Amazon.S3.Model;
using Sodium;
using Synccl.Core.Errors;
using Synccl.Core.Keys;
using Synccl.Core.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Synccl.Core.Device
{
    public class DeviceManager
    {
        private readonly string _root;
        private readonly IKeychain _keychain;
        private readonly ISecureSigner _secureSigner;

        public DeviceManager(string root, IKeychain keychain, ISecureSigner signer)
        {
            _root = root;
            _keychain = keychain;
            _secureSigner = signer;
        }

        public Devices? GetDevices()
        {
            var currentDevicePath = Path.Combine(_root, ".synccl", "devices.json");
            if (File.Exists(currentDevicePath))
            {
                var json = File.ReadAllText(currentDevicePath);
                try
                {
                    var existingDevices = JsonSerializer.Deserialize<Devices>(json);
                    if (existingDevices != null)
                    {
                        return existingDevices;
                    }
                }
                catch { }
                return null;
            }
            else
            {
                var devices = new Devices
                {
                    DeviceList = new List<Device>()
                };
                var newJson = JsonSerializer.Serialize(devices, new JsonSerializerOptions { WriteIndented = true });
                File.Create(currentDevicePath).Close();
                File.WriteAllText(currentDevicePath, newJson);
                return devices;
            }
        }

        public Guid GetCurrentDeviceId()
        {
            var publicKey = _secureSigner.GetDevicePublicKey();
            return new Guid(GenericHash.Hash(publicKey, null, 16));
        }

        public byte[] GetDeviceSigningPublicKey()
        {
            var publicKey = _secureSigner.GetDevicePublicKey();
            return publicKey;
        }

        public Device? GetDevice(Guid deviceId)
        {
            var devices = GetDevices();
            if (devices == null)
            {
                return null;
            }
            var device = devices.DeviceList.FirstOrDefault(d => d.DeviceId == deviceId);
            return device;
        }

        public Device GetOrCreateCurrentDevice()
        {
            var devices = GetDevices();
            if (devices == null)
            {
                throw new InvalidOperationException("Failed to get or create devices.");
            }

            var deviceId = GetCurrentDeviceId();
            var existingDevice = devices.DeviceList.FirstOrDefault(d => d.DeviceId == deviceId);
            if (existingDevice != null)
            {
                return existingDevice;
            }

            var publicKey = GetDeviceSigningPublicKey();
            var device = new Device
            {
                DeviceId = deviceId,
                UserId = Guid.NewGuid(),
                Username = Environment.UserName,
                SigningPublicKey = publicKey
            };

            AddOrSaveDevice(device);
            return device;
        }

        public bool AddOrSaveDevice(Device device)
        {
            var devices = GetDevices();
            if (devices == null)
            {
                return false;
            }

            var existingDevice = devices.DeviceList.FirstOrDefault(d => d.DeviceId == device.DeviceId);
            if (existingDevice != null)
            {
                devices.DeviceList.Remove(existingDevice);
            }

            devices.DeviceList.Add(device);

            var currentDevicePath = Path.Combine(_root, ".synccl", "devices.json");
            var newJson = JsonSerializer.Serialize(devices, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(currentDevicePath, newJson);
            return true;
        }

        public void RemoveDevice(Guid deviceId)
        {
            var devices = GetDevices();
            if (devices == null)
            {
                return;
            }

            var existingDevice = devices.DeviceList.FirstOrDefault(d => d.DeviceId == deviceId);
            if (existingDevice != null)
            {
                devices.DeviceList.Remove(existingDevice);
            }

            var currentDevicePath = Path.Combine(_root, ".synccl", "devices.json");
            var newJson = JsonSerializer.Serialize(devices, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(currentDevicePath, newJson);
        }

        public bool ChangeDeviceUsername(string username)
        {
            var device = GetOrCreateCurrentDevice();
            if (device == null)
            {
                return false;
            }

            device.Username = username;
            return true;
        }

        // Vault Encryption Key Management
        public void AddOrUpdateVaultEncryptionKey(string vaultName, byte[] vaultPubKey, Guid? deviceId = null)
        {
            var devices = GetDevices();
            if (devices == null)
            {
                throw new InvalidOperationException("Failed to get devices.");
            }

            deviceId = deviceId ?? GetCurrentDeviceId();
            var device = devices.DeviceList.FirstOrDefault(d => d.DeviceId == deviceId);
            if (device == null)
            {
                throw new InvalidOperationException("Device not found.");
            }

            if (string.IsNullOrWhiteSpace(device.VaultEncryptionKey.Name))
            {
                device.VaultEncryptionKey = new VaultEncryptionKey
                {
                    Name = vaultName,
                    PublicKey = vaultPubKey,
                    NamespaceEncryptionKeys = new List<NamespaceEncryptionKey>()
                };
            }
            else if (device.VaultEncryptionKey.Name != vaultName)
            {
                throw new InvalidOperationException("Vault name does not match the existing vault encryption key.");
            }

            device.VaultEncryptionKey.PublicKey = vaultPubKey;
            var currentDevicePath = Path.Combine(_root, ".synccl", "devices.json");
            var newJson = JsonSerializer.Serialize(devices, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(currentDevicePath, newJson);
        }

        public byte[]? GetDeviceVaultPubKey(string vaultName, Guid? deviceId = null)
        {
            var devices = GetDevices();
            if (devices == null)
            {
                return null;
            }

            deviceId = deviceId ?? GetCurrentDeviceId();
            var device = devices.DeviceList.FirstOrDefault(d => d.DeviceId == deviceId);
            if (device == null)
            {
                return null;
            }

            if (device.VaultEncryptionKey.Name != vaultName)
            {
                return null;
            }

            return device.VaultEncryptionKey.PublicKey;
        }

        // Namespace Encryption Key Management
        public void AddOrUpdateNamespaceEncryptionKey(string vaultName, string nsName, byte[] nsPubKey, Guid? deviceId = null)
        {
            var devices = GetDevices();
            if (devices == null)
            {
                throw new InvalidOperationException("Failed to get devices.");
            }

            deviceId = deviceId ?? GetCurrentDeviceId();
            var device = devices.DeviceList.FirstOrDefault(d => d.DeviceId == deviceId);
            if (device == null)
            {
                throw new InvalidOperationException("Device not found.");
            }

            if (device.VaultEncryptionKey.Name != vaultName)
            {
                throw new InvalidOperationException("Vault name does not match the existing vault encryption key.");
            }

            var nsKey = device.VaultEncryptionKey.NamespaceEncryptionKeys?.FirstOrDefault(nk => nk.NamespaceName == nsName);
            if (nsKey == null)
            {
                nsKey = new NamespaceEncryptionKey
                {
                    NamespaceName = nsName,
                    PublicKey = nsPubKey,
                    ItemEncryptionKeys = new List<ItemEncryptionKey>()
                };
                device.VaultEncryptionKey.NamespaceEncryptionKeys?.Add(nsKey);
            }
            else
            {
                nsKey.PublicKey = nsPubKey;
            }

            var currentDevicePath = Path.Combine(_root, ".synccl", "devices.json");
            var newJson = JsonSerializer.Serialize(devices, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(currentDevicePath, newJson);
        }

        public byte[]? GetDeviceNamespacePubKey(string vaultName, string nsName, Guid? deviceId = null)
        {
            var devicesPath = Path.Combine(_root, ".synccl", "devices.json");
            if (!File.Exists(devicesPath))
            {
                return null;
            }

            var json = File.ReadAllText(devicesPath);
            var devices = JsonSerializer.Deserialize<Devices>(json);
            if (devices == null)
            {
                return null;
            }

            deviceId = deviceId ?? GetCurrentDeviceId();
            var device = devices.DeviceList.FirstOrDefault(d => d.DeviceId == deviceId);
            if (device == null)
            {
                return null;
            }

            if (device.VaultEncryptionKey.Name != vaultName)
            {
                return null;
            }

            var nsKey = device.VaultEncryptionKey.NamespaceEncryptionKeys?.FirstOrDefault(nk => nk.NamespaceName == nsName);
            if (nsKey == null)
            {
                return null;
            }

            return nsKey.PublicKey;
        }

        // Item Encryption Key Management
        public void AddOrUpdateItemEncryptionKey(string vaultName, string nsName, string key, byte[] itemPubKey, Guid? deviceId = null)
        {
            var devices = GetDevices();
            if (devices == null)
            {
                throw new InvalidOperationException("Failed to get devices.");
            }

            deviceId = deviceId ?? GetCurrentDeviceId();
            var device = devices.DeviceList.FirstOrDefault(d => d.DeviceId == deviceId);
            if (device == null)
            {
                throw new InvalidOperationException("Device not found.");
            }

            if (device.VaultEncryptionKey.Name != vaultName)
            {
                throw new InvalidOperationException("Vault name does not match the existing vault encryption key.");
            }

            var nsKey = device.VaultEncryptionKey.NamespaceEncryptionKeys?.FirstOrDefault(nk => nk.NamespaceName == nsName);
            if (nsKey == null)
            {
                throw new InvalidOperationException("Namespace encryption key not found.");
            }

            var itemKey = nsKey.ItemEncryptionKeys?.FirstOrDefault(ik => ik.Key == key);
            if (itemKey == null)
            {
                itemKey = new ItemEncryptionKey
                {
                    Key = key,
                    PublicKey = itemPubKey
                };
                nsKey.ItemEncryptionKeys?.Add(itemKey);
            }
            else
            {
                itemKey.PublicKey = itemPubKey;
            }

            var currentDevicePath = Path.Combine(_root, ".synccl", "devices.json");
            var newJson = JsonSerializer.Serialize(devices, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(currentDevicePath, newJson);
        }

        public byte[]? GetDeviceItemPubKey(string vaultName, string nsName, string key, Guid? deviceId = null)
        {
            var devicesPath = Path.Combine(_root, ".synccl", "devices.json");
            if (!File.Exists(devicesPath))
            {
                return null;
            }

            var json = File.ReadAllText(devicesPath);
            var devices = JsonSerializer.Deserialize<Devices>(json);
            if (devices == null)
            {
                return null;
            }

            deviceId = deviceId ?? GetCurrentDeviceId();
            var device = devices.DeviceList.FirstOrDefault(d => d.DeviceId == deviceId);
            if (device == null)
            {
                return null;
            }

            if (device.VaultEncryptionKey.Name != vaultName)
            {
                return null;
            }

            var nsKey = device.VaultEncryptionKey.NamespaceEncryptionKeys?.FirstOrDefault(nk => nk.NamespaceName == nsName);
            if (nsKey == null)
            {
                return null;
            }

            var itemKey = nsKey.ItemEncryptionKeys?.FirstOrDefault(ik => ik.Key == key);
            if (itemKey == null)
            {
                return null;
            }

            return itemKey.PublicKey;
        }
    }
}
