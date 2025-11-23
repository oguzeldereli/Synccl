using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Device
{
    public class Devices
    {   
        public List<Device> DeviceList { get; set; } = new();
    }

    public class Device
    {
        public Guid DeviceId { get; set; }
        public Guid UserId { get; set; }
        public string Username { get; set; } = string.Empty;
        public byte[] SigningPublicKey { get; set; } = Array.Empty<byte>();
        public VaultEncryptionKey VaultEncryptionKey { get; set; } = new();
    }

    public class VaultEncryptionKey
    {
        public string Name { get; set; } = string.Empty;
        public byte[] PublicKey { get; set; } = Array.Empty<byte>();
        public List<NamespaceEncryptionKey> NamespaceEncryptionKeys { get; set; } = new();
    }

    public class NamespaceEncryptionKey
    {
        public string NamespaceName { get; set; } = string.Empty;
        public byte[] PublicKey { get; set; } = Array.Empty<byte>();
        public List<ItemEncryptionKey> ItemEncryptionKeys { get; set; } = new();
    }

    public class ItemEncryptionKey
    {
        public string Key { get; set; } = string.Empty;
        public byte[] PublicKey { get; set; } = Array.Empty<byte>();
    }
}
