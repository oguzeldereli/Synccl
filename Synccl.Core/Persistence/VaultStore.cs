using Newtonsoft.Json;
using Synccl.Core.Interfaces;
using Synccl.Core.Model;
using Synccl.Core.Persistence.Dto;

namespace Synccl.Core.Persistence
{
    /// <summary>
    /// Stores vaults as JSON files inside a <c>.synccl</c> directory.
    /// The directory is discovered by walking up from the current working
    /// directory, mirroring the pattern used by Git.
    /// </summary>
    public sealed class VaultStore : IVaultStore
    {
        private const string StoreDirName = ".synccl";
        private const string VaultExtension = ".vault.json";

        private static readonly JsonSerializerSettings JsonSettings = new()
        {
            Formatting = Formatting.Indented,
            NullValueHandling = NullValueHandling.Ignore
        };

        // ------------------------------------------------------------------ //
        //  Directory resolution
        // ------------------------------------------------------------------ //

        public string ResolveStoreDirectory(bool createIfMissing = false)
        {
            var dir = new DirectoryInfo(Directory.GetCurrentDirectory());
            while (dir is not null)
            {
                var candidate = Path.Combine(dir.FullName, StoreDirName);
                if (Directory.Exists(candidate))
                    return candidate;
                dir = dir.Parent;
            }

            // None found — create at cwd when asked.
            if (createIfMissing)
            {
                var newDir = Path.Combine(Directory.GetCurrentDirectory(), StoreDirName);
                Directory.CreateDirectory(newDir);
                return newDir;
            }

            throw new DirectoryNotFoundException(
                $"No '{StoreDirName}' directory found in '{Directory.GetCurrentDirectory()}' or any parent directory. " +
                "Run 'synccl init' first.");
        }

        // ------------------------------------------------------------------ //
        //  CRUD
        // ------------------------------------------------------------------ //

        public void Save(EncryptedLocalVaultDto vault, string storeDirectory)
        {
            EnsureDirectory(storeDirectory);
            var path = VaultPath(vault.Name, storeDirectory);
            var json = JsonConvert.SerializeObject(vault, JsonSettings);
            File.WriteAllText(path, json);
        }

        public EncryptedLocalVaultDto? Load(string vaultName, string storeDirectory)
        {
            var path = VaultPath(vaultName, storeDirectory);
            if (!File.Exists(path)) return null;

            var json = File.ReadAllText(path);
            return JsonConvert.DeserializeObject<EncryptedLocalVaultDto>(json, JsonSettings);
        }

        public void Delete(string vaultName, string storeDirectory)
        {
            var path = VaultPath(vaultName, storeDirectory);
            if (File.Exists(path))
                File.Delete(path);
        }

        public bool Exists(string vaultName, string storeDirectory)
            => File.Exists(VaultPath(vaultName, storeDirectory));

        public string GetVaultFilePath(string vaultName, string storeDirectory)
            => VaultPath(vaultName, storeDirectory);

        public IReadOnlyList<VaultInfo> ListVaults(string storeDirectory)
        {
            if (!Directory.Exists(storeDirectory))
                return [];

            var result = new List<VaultInfo>();
            foreach (var file in Directory.GetFiles(storeDirectory, $"*{VaultExtension}"))
            {
                try
                {
                    var json = File.ReadAllText(file);
                    var dto = JsonConvert.DeserializeObject<EncryptedLocalVaultDto>(json, JsonSettings);
                    if (dto is not null)
                        result.Add(VaultMapper.ToVaultInfo(dto, file));
                }
                catch
                {
                    // Skip malformed files.
                }
            }
            return result;
        }

        // ------------------------------------------------------------------ //
        //  Helpers
        // ------------------------------------------------------------------ //

        private static string VaultPath(string vaultName, string storeDirectory)
            => Path.Combine(storeDirectory, $"{SanitiseName(vaultName)}{VaultExtension}");

        private static string SanitiseName(string name)
        {
            // Replace characters that are invalid in file names with underscores.
            var invalid = Path.GetInvalidFileNameChars();
            return new string(name.Select(c => invalid.Contains(c) ? '_' : c).ToArray());
        }

        private static void EnsureDirectory(string path)
        {
            if (!Directory.Exists(path))
                Directory.CreateDirectory(path);
        }
    }
}
