using Amazon.S3.Model;
using Sodium;
using Synccl.Core.Errors;
using Synccl.Core.Keys;
using Synccl.Core.Vault;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Synccl.Core.Device
{
    public class DeviceManager
    {
        private readonly string _root;
        private readonly IKeychain _keychain;

        public DeviceManager(string root, IKeychain keychain)
        {
            _root = root;
            _keychain = keychain;
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
            }

            return null;
        }

        public Vault.Device GetOrCreateCurrentDevice()
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
                        var currentDevice = existingDevices.DeviceList.FirstOrDefault(d => d.DeviceId == existingDevices.CurrentDeviceId);
                        if (currentDevice != null)
                        {
                            return currentDevice;
                        }
                    }
                }
                catch { }
            }

            var keyPair = PublicKeyBox.GenerateKeyPair();
            var device = new Vault.Device
            {
                DeviceId = Guid.NewGuid(),
                UserId = Guid.NewGuid(),
                Username = Environment.UserName,
                SigningPublicKey = keyPair.PublicKey
            };

            var devices = new Devices
            {
                CurrentDeviceId = device.DeviceId,
                DeviceList = new List<Vault.Device> { device }
            };

            var newJson = JsonSerializer.Serialize(devices);

            File.Create(currentDevicePath).Close();
            File.WriteAllText(currentDevicePath, newJson);

            var account = $"synccl:device:{device.DeviceId}:signingPrivateKey";
            _keychain.TrySetKey(account, keyPair.PrivateKey);

            return device;
        }

        public bool SaveDevice(Vault.Device device)
        {
            var currentDevicePath = Path.Combine(_root, ".synccl", "devices.json");
            Devices devices;
            if (File.Exists(currentDevicePath))
            {
                var json = File.ReadAllText(currentDevicePath);
                try
                {
                    devices = JsonSerializer.Deserialize<Devices>(json) ?? new Devices();
                }
                catch
                {
                    devices = new Devices();
                }
            }
            else
            {
                devices = new Devices();
            }

            var existingDevice = devices.DeviceList.FirstOrDefault(d => d.DeviceId == device.DeviceId);
            if (existingDevice != null)
            {
                devices.DeviceList.Remove(existingDevice);
            }

            devices.DeviceList.Add(device);
            if (devices.CurrentDeviceId == Guid.Empty)
            {
                devices.CurrentDeviceId = device.DeviceId;
            }

            var newJson = JsonSerializer.Serialize(devices);
            File.WriteAllText(currentDevicePath, newJson);
            return true;
        }

        public byte[]? GetDevicePubKey(string vaultName, Guid? deviceId = null)
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

            if (deviceId == null)
            {
                var currentDevice = devices.DeviceList.FirstOrDefault(d => d.DeviceId == devices.CurrentDeviceId);
                if (currentDevice == null)
                {
                    return null;
                }

                if (currentDevice.VaultEncryptionKey.Name != vaultName)
                {
                    return null;
                }

                return currentDevice.VaultEncryptionKey.PublicKey;
            }

            var device = devices.DeviceList.FirstOrDefault(d => d.DeviceId == deviceId);
            if (device == null)
            {
                return null;
            }

            return device.VaultEncryptionKey.PublicKey;
        }

        public byte[]? GetDevicePubKey(string vaultName, string nsName, Guid? deviceId = null)
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

            if (deviceId == null)
            {
                var currentDevice = devices.DeviceList.FirstOrDefault(d => d.DeviceId == devices.CurrentDeviceId);
                if (currentDevice == null)
                {
                    return null;
                }

                if (currentDevice.VaultEncryptionKey.Name != vaultName)
                {
                    return null;
                }

                var nsKey = currentDevice.VaultEncryptionKey.NamespaceEncryptionKeys?.FirstOrDefault(nk => nk.NamespaceName == nsName);
                if (nsKey == null)
                {
                    return null;
                }

                return nsKey.PublicKey;
            }

            var device = devices.DeviceList.FirstOrDefault(d => d.DeviceId == deviceId);
            if (device == null)
            {
                return null;
            }

            var deviceNsKey = device.VaultEncryptionKey.NamespaceEncryptionKeys?.FirstOrDefault(nk => nk.NamespaceName == nsName);
            if (deviceNsKey == null)
            {
                return null;
            }

            return deviceNsKey.PublicKey;
        }

        public byte[]? GetDevicePubKey(string vaultName, string nsName, string key, Guid? deviceId = null)
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

            if (deviceId == null)
            {
                var currentDevice = devices.DeviceList.FirstOrDefault(d => d.DeviceId == devices.CurrentDeviceId);
                if (currentDevice == null)
                {
                    return null;
                }

                if (currentDevice.VaultEncryptionKey.Name != vaultName)
                {
                    return null;
                }

                var nsKey = currentDevice.VaultEncryptionKey.NamespaceEncryptionKeys?.FirstOrDefault(nk => nk.NamespaceName == nsName);
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

            var device = devices.DeviceList.FirstOrDefault(d => d.DeviceId == deviceId);
            if (device == null)
            {
                return null;
            }

            var deviceNsKey = device.VaultEncryptionKey.NamespaceEncryptionKeys?.FirstOrDefault(nk => nk.NamespaceName == nsName);
            if (deviceNsKey == null)
            {
                return null;
            }

            var deviceItemKey = deviceNsKey.ItemEncryptionKeys?.FirstOrDefault(ik => ik.Key == key);
            if (deviceItemKey == null)
            {
                return null;
            }

            return deviceItemKey.PublicKey;
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
    }
}
