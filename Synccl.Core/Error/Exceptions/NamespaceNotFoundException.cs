using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Error.Exceptions
{
    public class NamespaceNotFoundException : Exception
    {
        public NamespaceNotFoundException(string ns, string vault) 
            : base($"Namespace '{ns}' not found in vault '{vault}'.") { }
    }
}
