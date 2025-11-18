using Spectre.Console;
using Synccl.Core.Crypto;
using Synccl.Core.Errors;
using Synccl.Core.Keys;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Synccl.Core.Vault
{
    public interface IVaultService
    {
        public ServiceResponse<VaultModel> InitVault();
        public ServiceResponse<VaultModel> LoadVault();
        public ServiceResponse<VaultModel> TryLoadVault();
        public ServiceResponse Save(VaultModel vault);
        public ServiceResponse CreateNamespace(VaultModel vault, string namespaceName);
        public ServiceResponse DeleteNamespace(VaultModel vault, string namespaceName);
        public ServiceResponse<string> GetSecret(VaultModel vault, string namespaceName, string key);
        public ServiceResponse SetSecret(VaultModel vault, string namespaceName, string key, string value);
        public ServiceResponse UnsetSecret(VaultModel vault, string namespaceName, string key);
        public ServiceResponse<Dictionary<string, string>> ExportPlaintext(VaultModel vault, string namespaceName);
        public ServiceResponse ImportPlaintext(VaultModel vault, IDictionary<string, string> newPlaintextSecrets, string namespaceName);
    }
}