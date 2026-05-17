using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Entities.Model.Vault
{
    public class LocalItem
    {
        public string Key { get; private set; }
        public string Value { get; set; }

        private LocalItem(string key, string value)
        {
            Key = key;
            Value = value;
        }

        public static LocalItem From(string key, string value)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentException("Key cannot be null or whitespace.", nameof(key));
            }

            if (string.IsNullOrWhiteSpace(value)) 
            {
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(value));
            }

            return new LocalItem(key, value);
        }

        public static LocalItem From(LocalItem item)
        {
            return new LocalItem(item.Key, item.Value);
        }
    }
}
