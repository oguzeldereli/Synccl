using Synccl.Core.Enums;
using Synccl.Core.Model;

namespace Synccl.Core.Interfaces
{
    /// <summary>
    /// High-level vault service — the entry point for all CLI commands.
    /// </summary>
    public interface IVaultService
    {
        // ---- Vault lifecycle ----
            VaultInfo InitVault(string vaultName, string defaultNamespaceName, string? storeDirectory = null);
            VaultInfo CreateVault(string vaultName, string defaultNamespaceName, string? storeDirectory = null);
            void DestroyVault(string vaultName, string? storeDirectory = null);
        VaultInfo GetVaultInfo(string vaultName, string? storeDirectory = null);
        IReadOnlyList<VaultInfo> ListVaults(string? storeDirectory = null);
        void RenameVault(string vaultName, string newName, string? storeDirectory = null);

        // ---- Single-item operations ----
        void SetSecret(string vaultName, string namespaceName, string key, string value, UnlockContext unlock, string? storeDirectory = null);
        string GetSecret(string vaultName, string namespaceName, string key, UnlockContext unlock, string? storeDirectory = null);
        void UnsetSecret(string vaultName, string namespaceName, string key, string? storeDirectory = null);
        IReadOnlyDictionary<string, string> ListSecrets(string vaultName, string namespaceName, bool includeValues, UnlockContext unlock, string? storeDirectory = null);

        // ---- Namespace management ----
        void AddNamespace(string vaultName, string namespaceName, UnlockContext unlock, string? storeDirectory = null);
        void RemoveNamespace(string vaultName, string namespaceName, string? storeDirectory = null);
        IReadOnlyList<string> ListNamespaces(string vaultName, string? storeDirectory = null);

        // ---- Bulk operations ----
        DiffResult Diff(string sourceVault, string sourceNs, string destVault, string destNs, UnlockContext unlock, string? storeDirectory = null);
        void Push(string sourceVault, string sourceNs, string destVault, string destNs, UnlockContext unlock, bool dryRun, string? storeDirectory = null);
        void Pull(string sourceVault, string sourceNs, string destVault, string destNs, UnlockContext unlock, bool dryRun, string? storeDirectory = null);

        // ---- Import / Export ----
        void ImportFromFile(string vaultName, string namespaceName, string filePath, string format, UnlockContext unlock, string? storeDirectory = null);
        void ExportToFile(string vaultName, string namespaceName, string filePath, string format, UnlockContext unlock, string? storeDirectory = null);

        // ---- Run ----
        int RunProcess(string vaultName, string namespaceName, string executablePath, string[] args, UnlockContext unlock, string? storeDirectory = null);

        // ---- Key rotation ----
        void RotateVaultKey(string vaultName, UnlockContext unlock, bool rotateAll, string? storeDirectory = null);
        void RotateNamespaceKey(string vaultName, string namespaceName, UnlockContext unlock, bool rotateAll, string? storeDirectory = null);
        void RotateItemKey(string vaultName, string namespaceName, string itemKey, UnlockContext unlock, string? storeDirectory = null);

        // ---- Protect / Unprotect ----
        void Protect(string vaultName, UnlockContext currentUnlock, UnlockContext newProtection, string? storeDirectory = null);
        void Unprotect(string vaultName, UnlockContext currentUnlock, string? storeDirectory = null);
    }
}
