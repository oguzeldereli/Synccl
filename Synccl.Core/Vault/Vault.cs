using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Vault
{
    public class VaultModel
    {
        public Guid Id { get; set; }
        public List<KeyWrap> WrappedVaultKeys { get; set; } = new();
        public List<Namespace> Namespaces { get; set; } = new();
    }
        
    public class Namespace
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public List<KeyWrap> WrappedNamespaceKeys { get; set; } = new();
        public List<VaultSecret> Secrets { get; set; } = new();
    }

    public class VaultSecret
    {
        public string Key { get; set; } = string.Empty;
        public EncryptedBlob Payload { get; set; } = new();
        public List<KeyWrap> WrappedItemKeys { get; set; } = new();
    }

    public class EncryptedBlob
    {
        public string Algorithm { get; set; } = "xchacha20poly1305";
        public byte[] Ciphertext { get; set; } = Array.Empty<byte>();
        public byte[] Nonce { get; set; } = Array.Empty<byte>();
        public string? Aad { get; set; }
    }

    public class KeyWrap
    {
        public Guid DeviceId { get; set; }
        public Guid KeyId { get; set; }
        public byte[] DevicePublicKeyForWrap { get; set; } = Array.Empty<byte>();
        public byte[] WrappedKey { get; set; } = Array.Empty<byte>();
        public string WrapAlgorithm { get; set; } = "x25519-xchacha20";
        public int KeyVersion { get; set; }
        public KeyType Type { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        public enum KeyType
        {
            Item,
            Namespace,
            Vault
        }
    }
}
