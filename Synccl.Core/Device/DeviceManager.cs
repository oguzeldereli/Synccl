using Amazon.S3.Model;
using Sodium;
using Synccl.Core.Crypto;
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
        private readonly ISecureSigner _secureSigner;
        private readonly DeviceKeyService _deviceKeyService;

        public string VaultKeyAccountBase() => $"synccl:vault";
        public string NamespaceKeyAccountBase(string nsName) => $"synccl:vault:namespace:{nsName}";
        public string ItemKeyAccountBase(string nsName, string itemKey) => $"synccl:vault:namespace:{nsName}:item:{itemKey}";

        public DeviceManager(string root, ISecureSigner signer, DeviceKeyService deviceKeyService)
        {
            _root = root;
            _secureSigner = signer;
            _deviceKeyService = deviceKeyService;
        }

        public (byte[] pub, byte[] priv) GetOrCreateDeviceVaultKEK()
        {
            var vaultKeyAccount = 
            _deviceKeyService.GetOrCreate(VaultKeyAccountBase());
            return vaultKeyAccount;
        }

        public (byte[] pub, byte[] priv) GetDeviceVaultKEK()
        {
            var vaultKeyAccount = 
            _deviceKeyService.Get(VaultKeyAccountBase());
            return vaultKeyAccount;
        }

        public (byte[] pub, byte[] priv) GetOrCreateDeviceNamespaceKEK(string nsName)
        {
            var namespaceKeyAccount = 
            _deviceKeyService.GetOrCreate(NamespaceKeyAccountBase(nsName));
            return namespaceKeyAccount;
        }

        public (byte[] pub, byte[] priv) GetDeviceNamespaceKEK(string nsName)
        {
            var namespaceKeyAccount = 
            _deviceKeyService.Get(NamespaceKeyAccountBase(nsName));
            return namespaceKeyAccount;
        }

        public (byte[] pub, byte[] priv) GetOrCreateDeviceItemKEK(string nsName, string itemKey)
        {
            var itemKeyAccount = 
            _deviceKeyService.GetOrCreate(ItemKeyAccountBase(nsName, itemKey));
            return itemKeyAccount;
        }

        public (byte[] pub, byte[] priv) GetDeviceItemKEK(string nsName, string itemKey)
        {
            var itemKeyAccount = 
            _deviceKeyService.Get(ItemKeyAccountBase(nsName, itemKey));
            return itemKeyAccount;
        }

        public Devices? GetDevices(byte[] vk)
        {
            var currentDevicePath = Path.Combine(_root, ".synccl", "devices.json.enc");
            if (File.Exists(currentDevicePath))
            {
                var jsonEnc = File.ReadAllBytes(currentDevicePath);
                var json = Envelope.UnwrapDataWithKey(jsonEnc, vk);
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
                var newJsonEnc = Envelope.WrapDataWithKey(Encoding.UTF8.GetBytes(newJson), vk);
                File.Create(currentDevicePath).Close();
                File.WriteAllBytes(currentDevicePath, newJsonEnc);
                return devices;
            }
        }

        public void SaveDevices(Devices devices, byte[] vk)
        {
            var currentDevicePath = Path.Combine(_root, ".synccl", "devices.json.enc");
            var newJson = JsonSerializer.Serialize(devices, new JsonSerializerOptions { WriteIndented = true });
            var newJsonEnc = Envelope.WrapDataWithKey(Encoding.UTF8.GetBytes(newJson), vk);
            File.WriteAllBytes(currentDevicePath, newJsonEnc);
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

        public Device? GetDevice(Guid deviceId, byte[] vk)
        {   
            var devices = GetDevices(vk);
            if (devices == null)
            {
                return null;
            }
            var device = devices.DeviceList.FirstOrDefault(d => d.DeviceId == deviceId);
            return device;
        }

        public Device GetOrCreateCurrentDevice(byte[] vk)
        {
            var devices = GetDevices(vk);
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

            var signingPublicKey = GetDeviceSigningPublicKey();
            var publicWrappingKey = _deviceKeyService.GetDevicePublicWrappingKey();
            var device = new Device
            {
                DeviceId = deviceId,
                UserId = Guid.NewGuid(),
                Username = Environment.UserName,
                SigningPublicKey = signingPublicKey,
                WrappingPublicKey = publicWrappingKey,
            };

            AddOrSaveDevice(device, vk);
            return device;
        }

        public bool AddOrSaveDevice(Device device, byte[] vk)
        {
            var devices = GetDevices(vk);
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
            SaveDevices(devices, vk);
            return true;
        }

        public void RemoveDevice(Guid deviceId, byte[] vk)
        {
            var devices = GetDevices(vk);
            if (devices == null)
            {
                return;
            }

            var existingDevice = devices.DeviceList.FirstOrDefault(d => d.DeviceId == deviceId);
            if (existingDevice != null)
            {
                devices.DeviceList.Remove(existingDevice);
            }

            SaveDevices(devices, vk);
        }

        // Vault Encryption Key Management
        public void AddOrUpdateVaultEncryptionKey(byte[] vk, byte[] vaultPubKey, Guid? deviceId = null)
        {
            var devices = GetDevices(vk);
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

            device.VaultEncryptionKey.PublicKey = vaultPubKey;
            SaveDevices(devices, vk);
        }

        public byte[]? GetDeviceVaultPubKey(byte[] vk, Guid? deviceId = null)
        {
            var devices = GetDevices(vk);
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

            return device.VaultEncryptionKey.PublicKey;
        }

        // Namespace Encryption Key Management
        public void AddOrUpdateNamespaceEncryptionKey(byte[] vk, string nsName, byte[] nsPubKey, Guid? deviceId = null)
        {
            var devices = GetDevices(vk);
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
            
            SaveDevices(devices, vk);
        }

        public byte[]? GetDeviceNamespacePubKey(byte[] vk, string nsName, Guid? deviceId = null)
        {
            var devices = GetDevices(vk);
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

            var nsKey = device.VaultEncryptionKey.NamespaceEncryptionKeys?.FirstOrDefault(nk => nk.NamespaceName == nsName);
            if (nsKey == null)
            {
                return null;
            }

            return nsKey.PublicKey;
        }

        // Item Encryption Key Management
        public void AddOrUpdateItemEncryptionKey(byte[] vk, string nsName, string key, byte[] itemPubKey, Guid? deviceId = null)
        {
            var devices = GetDevices(vk);
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

            SaveDevices(devices, vk);
        }

        public byte[]? GetDeviceItemPubKey(byte[] vk, string nsName, string key, Guid? deviceId = null)
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
