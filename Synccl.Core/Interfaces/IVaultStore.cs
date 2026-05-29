using Synccl.Core.Model;
using Synccl.Core.Persistence.Dto;

namespace Synccl.Core.Interfaces
{
    /// <summary>
    /// Low-level persistence: reads/writes vault JSON files on disk.
    /// </summary>
    public interface IVaultStore
    {
        /// <summary>Returns the .synccl directory for the current working directory (walks up to find one, or creates at cwd).</summary>
        string ResolveStoreDirectory(bool createIfMissing = false);

        /// <summary>Save (create or overwrite) a vault file.</summary>
        void Save(EncryptedLocalVaultDto vault, string storeDirectory);

        /// <summary>Load a vault DTO by name. Returns null when not found.</summary>
        EncryptedLocalVaultDto? Load(string vaultName, string storeDirectory);

        /// <summary>Delete a vault file. No-op if file does not exist.</summary>
        void Delete(string vaultName, string storeDirectory);

        /// <summary>True when a vault file with that name exists.</summary>
        bool Exists(string vaultName, string storeDirectory);

        /// <summary>Returns the full path to the vault's JSON file (does not check existence).</summary>
        string GetVaultFilePath(string vaultName, string storeDirectory);

        /// <summary>List metadata for all vaults in the store directory.</summary>
        IReadOnlyList<VaultInfo> ListVaults(string storeDirectory);
    }
}
