using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Error.Exceptions
{
    public class NamespaceAlreadyExistsException : Exception
    {
        public NamespaceAlreadyExistsException(string ns, string vault) :
            base($"Namespace '{ns}' already exists in vault '{vault}'.") { }
    }
}
