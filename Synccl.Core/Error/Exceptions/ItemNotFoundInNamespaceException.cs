using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Error.Exceptions
{
    public class ItemNotFoundInNamespaceException : Exception
    {
        public ItemNotFoundInNamespaceException(string key, string ns)
            : base($"Item with key '{key}' not found in namespace '{ns}'.") { }
    }
}
