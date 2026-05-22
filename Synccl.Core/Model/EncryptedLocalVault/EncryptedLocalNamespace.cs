using Synccl.Core.Model.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Model.EncryptedLocalVault
{
    public class EncryptedLocalNamespace
    {
        private readonly List<KeyWrap> _wrappedNamespaceKeys;
        private readonly List<EncryptedLocalItem> _encryptedItems;

        public Guid Id { get; private set; }
        public string Name { get; private set; }

        private EncryptedLocalNamespace(
            Guid id, 
            string name, 
            List<KeyWrap> wrappedNamespaceKeys, 
            List<EncryptedLocalItem> encryptedLocalItems)
        {
            Id = id;
            Name = name;
            _wrappedNamespaceKeys = wrappedNamespaceKeys;
            _encryptedItems = encryptedLocalItems;  
        }
    }
}
