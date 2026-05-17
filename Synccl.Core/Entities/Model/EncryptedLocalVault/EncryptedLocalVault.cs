using Synccl.Core.Entities.Enums;
using Synccl.Core.Entities.Model.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Synccl.Core.Entities.Model.EncryptedVault
{
    public class EncryptedLocalVault
    {
        private readonly List<KeyWrap> _wrappedVaultKeys;
        private readonly List<EncryptedLocalNamespace> _encryptedNamespaces;
        private readonly List<Signature> _signatures;

        public EncryptedLocalVaultAccessMode AccessMode { get; private set; }
        public Guid Id { get; private set; }
        public string Name { get; private set; }
        public int Version { get; private set; }
        public string DefaultNamespace { get; private set; }

        private EncryptedLocalVault(
            EncryptedLocalVaultAccessMode accessMode,
            Guid id,
            string name,
            string defaultNamespace,
            int version,
            List<KeyWrap> wrappedVaultKeys,
            List<EncryptedLocalNamespace> encryptedNamespaces,
            List<Signature> signatures)
        {
            AccessMode = accessMode;   
            Id = id;
            Name = name;
            DefaultNamespace = defaultNamespace;
            Version = version;
            _wrappedVaultKeys = wrappedVaultKeys;
            _encryptedNamespaces = encryptedNamespaces;
            _signatures = signatures;
        }

        public string ToJSON()
        {
            return JsonSerializer.Serialize(this);
        }
    }
}
