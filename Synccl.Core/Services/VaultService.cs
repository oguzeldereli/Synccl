using Synccl.Core.Enums;
using Synccl.Core.Error.Exceptions;
using Synccl.Core.Interfaces;
using Synccl.Core.Model;
using Synccl.Core.Model.EncryptedLocalVault;
using Synccl.Core.Model.LocalVault;
using Synccl.Core.Persistence;
using System.Diagnostics;
using System.Text;

namespace Synccl.Core.Services
{
    public sealed class VaultService : IVaultService
    {
        private readonly IVaultStore _store;
        private readonly IVaultCryptoService _crypto;

        public VaultService(IVaultStore store, IVaultCryptoService crypto)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
            _crypto = crypto ?? throw new ArgumentNullException(nameof(crypto));
        }

        // ------------------------------------------------------------------ //
        //  Helpers
        // ------------------------------------------------------------------ //

        private string ResolveDir(string? storeDirectory, bool createIfMissing = false)
            => storeDirectory ?? _store.ResolveStoreDirectory(createIfMissing);

        private EncryptedLocalVault LoadVault(string vaultName, string storeDir)
        {
            var dto = _store.Load(vaultName, storeDir)
                ?? throw new VaultNotFoundException(vaultName);
            return VaultMapper.ToDomain(dto);
        }

        private void SaveVault(EncryptedLocalVault vault, string storeDir)
            => _store.Save(VaultMapper.ToDto(vault), storeDir);

        // ------------------------------------------------------------------ //
        //  Vault lifecycle
        // ------------------------------------------------------------------ //

        public VaultInfo InitVault(string vaultName, string defaultNamespaceName, string? storeDirectory = null)
        {
            var dir = ResolveDir(storeDirectory, createIfMissing: true);

            if (_store.Exists(vaultName, dir))
                throw new VaultAlreadyExistsException(vaultName);

            var vault = _crypto.InitialiseVault(vaultName, defaultNamespaceName);
            SaveVault(vault, dir);

            return VaultMapper.ToVaultInfo(VaultMapper.ToDto(vault), _store.GetVaultFilePath(vaultName, dir));
        }

        public VaultInfo CreateVault(string vaultName, string defaultNamespaceName, string? storeDirectory = null)
        {
            // Requires an existing .synccl directory; does NOT create one.
            var dir = ResolveDir(storeDirectory, createIfMissing: false);

            if (_store.Exists(vaultName, dir))
                throw new VaultAlreadyExistsException(vaultName);

            var vault = _crypto.InitialiseVault(vaultName, defaultNamespaceName);
            SaveVault(vault, dir);

            return VaultMapper.ToVaultInfo(VaultMapper.ToDto(vault), _store.GetVaultFilePath(vaultName, dir));
        }

        public void DestroyVault(string vaultName, string? storeDirectory = null)
        {
            var dir = ResolveDir(storeDirectory);
            if (!_store.Exists(vaultName, dir))
                throw new VaultNotFoundException(vaultName);
            _store.Delete(vaultName, dir);
        }

        public VaultInfo GetVaultInfo(string vaultName, string? storeDirectory = null)
        {
            var dir = ResolveDir(storeDirectory);
            var dto = _store.Load(vaultName, dir)
                ?? throw new VaultNotFoundException(vaultName);
            return VaultMapper.ToVaultInfo(dto, _store.GetVaultFilePath(vaultName, dir));
        }

        public IReadOnlyList<VaultInfo> ListVaults(string? storeDirectory = null)
        {
            var dir = ResolveDir(storeDirectory);
            return _store.ListVaults(dir);
        }

        public void RenameVault(string vaultName, string newName, string? storeDirectory = null)
        {
            var dir = ResolveDir(storeDirectory);
            var vault = LoadVault(vaultName, dir);

            if (_store.Exists(newName, dir))
                throw new VaultAlreadyExistsException(newName);

            vault.Rename(newName);
            SaveVault(vault, dir);
            _store.Delete(vaultName, dir);
        }

        // ------------------------------------------------------------------ //
        //  Single-item operations
        // ------------------------------------------------------------------ //

        public void SetSecret(
            string vaultName, string namespaceName, string key, string value,
            UnlockContext unlock, string? storeDirectory = null)
        {
            var dir = ResolveDir(storeDirectory);
            var vault = LoadVault(vaultName, dir);
            _crypto.SetItem(vault, namespaceName, key, value, unlock);
            SaveVault(vault, dir);
        }

        public string GetSecret(
            string vaultName, string namespaceName, string key,
            UnlockContext unlock, string? storeDirectory = null)
        {
            var dir = ResolveDir(storeDirectory);
            var vault = LoadVault(vaultName, dir);
            return _crypto.GetItem(vault, namespaceName, key, unlock);
        }

        public void UnsetSecret(
            string vaultName, string namespaceName, string key,
            string? storeDirectory = null)
        {
            var dir = ResolveDir(storeDirectory);
            var vault = LoadVault(vaultName, dir);
            _crypto.RemoveItem(vault, namespaceName, key);
            SaveVault(vault, dir);
        }

        public IReadOnlyDictionary<string, string> ListSecrets(
            string vaultName, string namespaceName, bool includeValues,
            UnlockContext unlock, string? storeDirectory = null)
        {
            var dir = ResolveDir(storeDirectory);
            var vault = LoadVault(vaultName, dir);

            var ns = vault.GetNamespace(namespaceName);
            var keys = ns.GetItemKeys();

            if (!includeValues)
                return keys.ToDictionary(k => k, _ => string.Empty);

            // Decrypt each value individually — no need to decrypt the whole vault.
            var result = new Dictionary<string, string>(keys.Count);
            foreach (var k in keys)
                result[k] = _crypto.GetItem(vault, namespaceName, k, unlock);

            return result;
        }

        // ------------------------------------------------------------------ //
        //  Namespace management
        // ------------------------------------------------------------------ //

        public void AddNamespace(
            string vaultName, string namespaceName,
            UnlockContext unlock, string? storeDirectory = null)
        {
            var dir = ResolveDir(storeDirectory);
            var vault = LoadVault(vaultName, dir);

            if (vault.ContainsNamespace(namespaceName))
                throw new NamespaceAlreadyExistsException(namespaceName, vaultName);

            // Build new namespace key wrapped by vault master key.
            var vaultKey = UnwrapVaultKey(vault, unlock);
            try
            {
                var nsKeyId = Guid.NewGuid();
                var nsKey = new byte[32];
                System.Security.Cryptography.RandomNumberGenerator.Fill(nsKey);
                try
                {
                    var keyWrapper = GetKeyWrapper();
                    var nsKeyWrap = keyWrapper.Wrap(
                        Enums.KeyWrapping.KeyWrappingProfile.ParentKeyXChaCha20Poly1305,
                        nsKeyId,
                        vault.WrappedVaultKeys[0].WrappedKeyId,
                        nsKey,
                        vaultKey,
                        $"vault:{vaultName}:ns:{namespaceName}");

                    var newNs = EncryptedLocalNamespace.CreateNew(namespaceName, [nsKeyWrap]);
                    vault.AddNamespace(newNs);
                }
                finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(nsKey); }
            }
            finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(vaultKey); }

            SaveVault(vault, dir);
        }

        public void RemoveNamespace(
            string vaultName, string namespaceName,
            string? storeDirectory = null)
        {
            var dir = ResolveDir(storeDirectory);
            var vault = LoadVault(vaultName, dir);
            vault.RemoveNamespace(namespaceName);
            SaveVault(vault, dir);
        }

        public IReadOnlyList<string> ListNamespaces(string vaultName, string? storeDirectory = null)
        {
            var dir = ResolveDir(storeDirectory);
            var vault = LoadVault(vaultName, dir);
            return vault.GetNamespaceNames();
        }

        // ------------------------------------------------------------------ //
        //  Bulk: Diff / Push / Pull
        // ------------------------------------------------------------------ //

        public DiffResult Diff(
            string sourceVault, string sourceNs,
            string destVault, string destNs,
            UnlockContext unlock, string? storeDirectory = null)
        {
            var dir = ResolveDir(storeDirectory);
            var src = _crypto.DecryptVault(LoadVault(sourceVault, dir), unlock);
            var dst = _crypto.DecryptVault(LoadVault(destVault, dir), unlock);

            var srcSnap = src.GetNamespaceSnapshot(sourceNs);
            var dstSnap = dst.GetNamespaceSnapshot(destNs);

            return DiffEngine.Compute(srcSnap, dstSnap);
        }

        public void Push(
            string sourceVault, string sourceNs,
            string destVault, string destNs,
            UnlockContext unlock, bool dryRun, string? storeDirectory = null)
        {
            var dir = ResolveDir(storeDirectory);
            var srcVault = _crypto.DecryptVault(LoadVault(sourceVault, dir), unlock);
            var dstVaultEnc = LoadVault(destVault, dir);
            var dstVault = _crypto.DecryptVault(dstVaultEnc, unlock);

            var srcSnap = srcVault.GetNamespaceSnapshot(sourceNs);
            foreach (var (key, item) in srcSnap.GetItems())
                dstVault.SetItem(key, item.Value, destNs);

            if (!dryRun)
            {
                var reEncrypted = _crypto.EncryptVault(dstVault, dstVaultEnc, unlock);
                SaveVault(reEncrypted, dir);
            }
        }

        public void Pull(
            string sourceVault, string sourceNs,
            string destVault, string destNs,
            UnlockContext unlock, bool dryRun, string? storeDirectory = null)
            => Push(sourceVault, sourceNs, destVault, destNs, unlock, dryRun, storeDirectory);

        // ------------------------------------------------------------------ //
        //  Import / Export
        // ------------------------------------------------------------------ //

        public void ImportFromFile(
            string vaultName, string namespaceName,
            string filePath, string format,
            UnlockContext unlock, string? storeDirectory = null)
        {
            var pairs = ParseFile(filePath, format);
            var dir = ResolveDir(storeDirectory);
            var vault = LoadVault(vaultName, dir);

            foreach (var (key, value) in pairs)
                _crypto.SetItem(vault, namespaceName, key, value, unlock);

            SaveVault(vault, dir);
        }

        public void ExportToFile(
            string vaultName, string namespaceName,
            string filePath, string format,
            UnlockContext unlock, string? storeDirectory = null)
        {
            var secrets = ListSecrets(vaultName, namespaceName, includeValues: true, unlock, storeDirectory);
            WriteFile(filePath, format, secrets);
        }

        // ------------------------------------------------------------------ //
        //  Run
        // ------------------------------------------------------------------ //

        public int RunProcess(
            string vaultName, string namespaceName,
            string executablePath, string[] args,
            UnlockContext unlock, string? storeDirectory = null)
        {
            var secrets = ListSecrets(vaultName, namespaceName, includeValues: true, unlock, storeDirectory);

            var psi = new ProcessStartInfo(executablePath)
            {
                UseShellExecute = false
            };

            foreach (var arg in args)
                psi.ArgumentList.Add(arg);

            foreach (var (key, value) in secrets)
                psi.Environment[key] = value;

            using var process = Process.Start(psi)
                ?? throw new InvalidOperationException($"Could not start process '{executablePath}'.");

            process.WaitForExit();
            return process.ExitCode;
        }

        // ------------------------------------------------------------------ //
        //  Key rotation
        // ------------------------------------------------------------------ //

        public void RotateVaultKey(
            string vaultName, UnlockContext unlock, bool rotateAll,
            string? storeDirectory = null)
        {
            var dir = ResolveDir(storeDirectory);
            var vault = LoadVault(vaultName, dir);
            var rotated = _crypto.RotateVaultKey(vault, unlock, rotateAll);
            SaveVault(rotated, dir);
        }

        public void RotateNamespaceKey(
            string vaultName, string namespaceName, UnlockContext unlock, bool rotateAll,
            string? storeDirectory = null)
        {
            var dir = ResolveDir(storeDirectory);
            var vault = LoadVault(vaultName, dir);
            _crypto.RotateNamespaceKey(vault, namespaceName, unlock, rotateAll);
            SaveVault(vault, dir);
        }

        public void RotateItemKey(
            string vaultName, string namespaceName, string itemKey,
            UnlockContext unlock, string? storeDirectory = null)
        {
            var dir = ResolveDir(storeDirectory);
            var vault = LoadVault(vaultName, dir);
            _crypto.RotateItemKey(vault, namespaceName, itemKey, unlock);
            SaveVault(vault, dir);
        }

        // ------------------------------------------------------------------ //
        //  Protect / Unprotect
        // ------------------------------------------------------------------ //

        public void Protect(
            string vaultName, UnlockContext currentUnlock, UnlockContext newProtection,
            string? storeDirectory = null)
        {
            var dir = ResolveDir(storeDirectory);
            var vault = LoadVault(vaultName, dir);
            _crypto.Protect(vault, currentUnlock, newProtection);
            SaveVault(vault, dir);
        }

        public void Unprotect(
            string vaultName, UnlockContext currentUnlock,
            string? storeDirectory = null)
        {
            var dir = ResolveDir(storeDirectory);
            var vault = LoadVault(vaultName, dir);
            _crypto.Unprotect(vault, currentUnlock);
            SaveVault(vault, dir);
        }

        // ------------------------------------------------------------------ //
        //  Import/Export helpers
        // ------------------------------------------------------------------ //

        private static IEnumerable<(string Key, string Value)> ParseFile(string path, string format)
        {
            var lines = File.ReadAllLines(path);
            return format.ToLowerInvariant() switch
            {
                "env" => ParseEnvLines(lines),
                "csv" => ParseCsvLines(lines),
                _ => throw new NotSupportedException($"Unsupported import format: '{format}'. Use 'env' or 'csv'.")
            };
        }

        private static IEnumerable<(string, string)> ParseEnvLines(string[] lines)
        {
            foreach (var raw in lines)
            {
                var line = raw.Trim();
                if (string.IsNullOrEmpty(line) || line.StartsWith('#')) continue;
                var eq = line.IndexOf('=');
                if (eq < 1) continue;
                var key = line[..eq].Trim();
                var value = line[(eq + 1)..].Trim().Trim('"');
                yield return (key, value);
            }
        }

        private static IEnumerable<(string, string)> ParseCsvLines(string[] lines)
        {
            foreach (var raw in lines.Skip(1)) // skip header
            {
                var parts = raw.Split(',', 2);
                if (parts.Length < 2) continue;
                yield return (parts[0].Trim().Trim('"'), parts[1].Trim().Trim('"'));
            }
        }

        private static void WriteFile(string path, string format, IReadOnlyDictionary<string, string> secrets)
        {
            var sb = new StringBuilder();
            switch (format.ToLowerInvariant())
            {
                case "env":
                    foreach (var (k, v) in secrets)
                        sb.AppendLine($"{k}={QuoteIfNeeded(v)}");
                    break;
                case "csv":
                    sb.AppendLine("key,value");
                    foreach (var (k, v) in secrets)
                        sb.AppendLine($"\"{k}\",\"{v.Replace("\"", "\"\"")}\"");
                    break;
                default:
                    throw new NotSupportedException($"Unsupported export format: '{format}'. Use 'env' or 'csv'.");
            }
            File.WriteAllText(path, sb.ToString());
        }

        private static string QuoteIfNeeded(string v)
            => v.Contains(' ') || v.Contains('"') ? $"\"{v.Replace("\"", "\\\"")}\"" : v;

        // ------------------------------------------------------------------ //
        //  Key wrapper access (for AddNamespace)
        // ------------------------------------------------------------------ //

        private Security.KeyWrapper GetKeyWrapper()
        {
            // The crypto service owns a KeyWrapper; expose via the cast.
            if (_crypto is VaultCryptoService svc)
                return svc.KeyWrapper;
            throw new InvalidOperationException("Unexpected IVaultCryptoService implementation.");
        }

        private byte[] UnwrapVaultKey(EncryptedLocalVault vault, UnlockContext unlock)
        {
            if (_crypto is VaultCryptoService svc)
                return svc.UnwrapVaultKeyPublic(vault, unlock);
            throw new InvalidOperationException("Unexpected IVaultCryptoService implementation.");
        }
    }
}
