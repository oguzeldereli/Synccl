using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Error.Exceptions
{
    public class VaultDefaultNamespaceCannotBeRemoved : Exception
    {
        public VaultDefaultNamespaceCannotBeRemoved(string defaultNs, string vault) : 
            base($"The default namespace '{defaultNs}' of vault '{vault}' cannot be removed.") { }
    }
}
