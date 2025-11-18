using Spectre.Console;
using Synccl.Core.Device;
using Synccl.Core.Errors;
using Synccl.Core.Vault;
using Synccl.Core.VaultCrypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using static Synccl.Core.Vault.KeyWrap;

namespace Synccl.Core.Vault
{
    public sealed class VaultService : IVaultService
    {
        private readonly string _vaultDir;
        private readonly string _vaultFile;
        private readonly string _vaultIdFile;
        private readonly DeviceManager _deviceManager;
        private readonly CurrentDeviceVaultKeyManager _keyManager;
        private readonly VaultCryptoEngine _crypto;

        public VaultService(string vaultDir, DeviceManager deviceManager, CurrentDeviceVaultKeyManager keyManager, VaultCryptoEngine crypto)
        {
            _vaultDir = vaultDir;
            _vaultFile = Path.Combine(vaultDir, "secrets.json");
            _vaultIdFile = Path.Combine(vaultDir, "id");
            _deviceManager = deviceManager;
            _keyManager = keyManager;
            _crypto = crypto;
        }

        // ---------------------------------------------------------------------
        // Lifecycle
        // ---------------------------------------------------------------------

        public ServiceResponse<VaultModel> InitVault()
        {
            if (File.Exists(_vaultFile))
                return ServiceResponse<VaultModel>.Fail("Vault already exists here.");

            if (!File.Exists(_vaultIdFile))
                return ServiceResponse<VaultModel>.Fail("Vault ID file is missing.");

            var vaultId = Guid.Parse(File.ReadAllText(_vaultIdFile).Trim());

            var vault = new VaultModel
            {
                Id = vaultId,
                Name = "default",
                fileName = Path.GetFileName(_vaultFile),
                Namespaces = new(),
                WrappedVaultKeys = new()
            };

            // --- Create VK ---
            var vk = _keyManager.GenerateSymmetricKey();
            var vkId = Guid.NewGuid();
            var vkWrap = _keyManager.WrapVKWithDK(vault.Name, vk, vkId, version: 1);
            vkWrap.Type = KeyWrap.KeyType.Vault;
            vault.WrappedVaultKeys.Add(vkWrap);

            // 🟢 Save vault WITH VK before creating namespaces
            Save(vault);

            // --- Create default namespace (creates NK and wraps for this device) ---
            var nsCreationResult = CreateNamespace(vault, "default");
            if (!nsCreationResult.Success)
                return ServiceResponse<VaultModel>.Fail("Failed to create default namespace.");

            return ServiceResponse<VaultModel>.Ok(vault);
        }

        public ServiceResponse<VaultModel> LoadVault()
        {
            if (!File.Exists(_vaultFile))
                return ServiceResponse<VaultModel>.Fail("No vault found here. Run `synccl init` first.");

            var json = File.ReadAllText(_vaultFile);
            var vault = JsonSerializer.Deserialize<VaultModel>(json);

            if (vault == null)
                return ServiceResponse<VaultModel>.Fail("Invalid vault file.");

            var currentDevice = _deviceManager.GetOrCreateCurrentDevice();
            var deviceAuthorized = vault.WrappedVaultKeys.Any(x => x.DeviceId == currentDevice.DeviceId);

            if (!deviceAuthorized)
                return ServiceResponse<VaultModel>.Fail("This device is not authorized for this vault. Run `synccl team request`.");

            return ServiceResponse<VaultModel>.Ok(vault);
        }

        public ServiceResponse<VaultModel> TryLoadVault()
            => File.Exists(_vaultFile)
            ? LoadVault()
            : ServiceResponse<VaultModel>.Fail("Couldn't load vault.");

        public ServiceResponse Save(VaultModel vault)
        {
            try
            {
                Directory.CreateDirectory(_vaultDir);
                var json = JsonSerializer.Serialize(vault, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(_vaultFile, json);
                return ServiceResponse.Ok();
            }
            catch (Exception ex)
            {
                return ServiceResponse.Fail($"Failed to save vault: {ex.Message}");
            }
        }

        // ---------------------------------------------------------------------
        // Key helpers (VK, NK, IK)
        // ---------------------------------------------------------------------

        private byte[] RequireVK(VaultModel vault)
        {
            var device = _deviceManager.GetOrCreateCurrentDevice();

            var vkWrap = vault.WrappedVaultKeys
                .FirstOrDefault(w => w.DeviceId == device.DeviceId && w.Type == KeyType.Vault)
                ?? throw new InvalidOperationException("No vault key wrap for this device.");

            return _keyManager.UnwrapVKWithDK(vault.Name, vkWrap);
        }

        private byte[] EnsureNKForCurrentDevice(VaultModel vault, Namespace ns)
        {
            var device = _deviceManager.GetOrCreateCurrentDevice();
            var myNkWrap = ns.WrappedNamespaceKeys
                .FirstOrDefault(w => w.DeviceId == device.DeviceId && w.Type == KeyType.Namespace);

            if (myNkWrap != null)
            {
                var vk = RequireVK(vault);
                return _keyManager.UnwrapNKWithVK(vault.Name, ns.Name, myNkWrap, vk);
            }

            if (ns.WrappedNamespaceKeys.Count > 0)
                throw new InvalidOperationException($"This device is not authorized for namespace '{ns.Name}'. Request access.");

            // First wrap for this namespace: create NK and wrap it for current device
            var newNk = _keyManager.GenerateSymmetricKey();
            var vkForWrap = RequireVK(vault);
            var nkId = Guid.NewGuid();

            var newNkWrap = _keyManager.WrapNKWithVKAndDK(vault.Name, ns.Name, newNk, vkForWrap, nkId, version: 1);
            newNkWrap.Type = KeyType.Namespace;
            ns.WrappedNamespaceKeys.Add(newNkWrap);

            return newNk;
        }

        private byte[] RequireNKForCurrentDevice(VaultModel vault, Namespace ns)
        {
            var device = _deviceManager.GetOrCreateCurrentDevice();
            var myNkWrap = ns.WrappedNamespaceKeys
                .FirstOrDefault(w => w.DeviceId == device.DeviceId && w.Type == KeyType.Namespace)
                ?? throw new InvalidOperationException($"This device is not authorized for namespace '{ns.Name}'. Request access.");

            var vk = RequireVK(vault);
            return _keyManager.UnwrapNKWithVK(vault.Name, ns.Name, myNkWrap, vk);
        }

        private byte[] RequireIKForCurrentDevice(VaultModel vault, Namespace ns, VaultSecret secret)
        {
            var device = _deviceManager.GetOrCreateCurrentDevice();
            var myIkWrap = secret.WrappedItemKeys
                .FirstOrDefault(w => w.DeviceId == device.DeviceId && w.Type == KeyType.Item)
                ?? throw new InvalidOperationException($"This device is not authorized for secret '{secret.Key}'. Request access.");

            var nk = RequireNKForCurrentDevice(vault, ns);
            return _keyManager.UnwrapIKWithNK(vault.Name, ns.Name, secret.Key, myIkWrap, nk);
        }

        private void EnsureIKWrapForCurrentDevice(VaultModel vault, Namespace ns, VaultSecret secret, byte[] ik, Guid ikId, int version)
        {
            var device = _deviceManager.GetOrCreateCurrentDevice();
            if (secret.WrappedItemKeys.Any(w => w.DeviceId == device.DeviceId && w.Type == KeyType.Item))
                return;

            var nk = RequireNKForCurrentDevice(vault, ns);
            var wrap = _keyManager.WrapIKWithNK(vault.Name, ns.Name, secret.Key, ik, nk, ikId, version);
            wrap.Type = KeyType.Item;

            secret.WrappedItemKeys.RemoveAll(w => w.DeviceId == device.DeviceId && w.Type == KeyType.Item);
            secret.WrappedItemKeys.Add(wrap);
        }

        // ---------------------------------------------------------------------
        // Namespaces
        // ---------------------------------------------------------------------

        public ServiceResponse CreateNamespace(VaultModel vault, string namespaceName)
        {
            if (vault.Namespaces.Any(n => n.Name == namespaceName))
                return ServiceResponse.Fail($"Namespace [blue]{namespaceName}[/] already exists.");

            var ns = new Namespace
            {
                Id = Guid.NewGuid(),
                Name = namespaceName,
                WrappedNamespaceKeys = new(),
                Secrets = new()
            };

            var vk = RequireVK(vault);
            var nk = _keyManager.GenerateSymmetricKey();
            var nkId = Guid.NewGuid();
            var nkWrap = _keyManager.WrapNKWithVKAndDK(vault.Name, namespaceName, nk, vk, nkId, version: 1);
            nkWrap.Type = KeyType.Namespace;

            ns.WrappedNamespaceKeys.Add(nkWrap);

            vault.Namespaces.Add(ns);

            return ServiceResponse.Ok();
        }

        public ServiceResponse DeleteNamespace(VaultModel vault, string namespaceName)
        {
            var ns = vault.Namespaces.FirstOrDefault(n => n.Name == namespaceName);
            if (ns == null)
                return ServiceResponse.Fail($"Namespace [blue]{namespaceName}[/] not found.");
            var device = _deviceManager.GetOrCreateCurrentDevice();
            var myNkWrap = ns.WrappedNamespaceKeys.FirstOrDefault(w => w.DeviceId == device.DeviceId && w.Type == KeyType.Namespace);
            if (myNkWrap == null)
                return ServiceResponse.Fail($"This device is not authorized for namespace [blue]{namespaceName}[/]. Request access.");

            var removed = vault.Namespaces.RemoveAll(n => n.Name == namespaceName) > 0;
            if (removed)
            {
                return ServiceResponse.Ok();
            }
            return ServiceResponse.Fail($"Failed to delete namespace [blue]{namespaceName}[/].");
        }

        // ---------------------------------------------------------------------
        // Secrets
        // ---------------------------------------------------------------------

        public ServiceResponse<string> GetSecret(VaultModel vault, string namespaceName, string key)
        {
            var ns = vault.Namespaces.FirstOrDefault(n => n.Name == namespaceName);
            if (ns == null)
                return ServiceResponse<string>.Fail($"Namespace [blue]{namespaceName}[/] not found in vault.");

            var secret = ns.Secrets.FirstOrDefault(s => s.Key == key);
            if (secret == null)
                return ServiceResponse<string>.Fail($"Secret withh key [blue]{namespaceName}::{key}[/] not found in namespace.");

            var ik = RequireIKForCurrentDevice(vault, ns, secret);
            var plaintext = _crypto.DecryptValue(secret.Payload, ik);
            return ServiceResponse<string>.Ok(Encoding.UTF8.GetString(plaintext));
        }

        public ServiceResponse SetSecret(VaultModel vault, string namespaceName, string key, string value)
        {
            if (!vault.Namespaces.Any(n => n.Name == namespaceName))
            {
                var nsCreationResult = CreateNamespace(vault, namespaceName);
                if (!nsCreationResult.Success)
                    return nsCreationResult;
            }

            var ns = vault.Namespaces.FirstOrDefault(n => n.Name == namespaceName);
            if (ns == null)
                return ServiceResponse.Fail($"Namespace [blue]{namespaceName}[/] not found in vault after creation attempt.");

            // Ensure we have NK for this device (creates if namespace is new)
            var nk = EnsureNKForCurrentDevice(vault, ns);

            var secret = ns.Secrets.FirstOrDefault(s => s.Key == key);
            byte[] ik;
            Guid ikId;
            int keyVersion;

            if (secret == null)
            {
                // Create new item
                secret = new VaultSecret { Key = key, Payload = new EncryptedBlob(), WrappedItemKeys = new() };
                ns.Secrets.Add(secret);

                ik = _keyManager.GenerateSymmetricKey();
                ikId = Guid.NewGuid();
                keyVersion = 1;
            }
            else
            {
                // Update existing — must have IK wrap for this device
                var device = _deviceManager.GetOrCreateCurrentDevice();
                var myIkWrap = secret.WrappedItemKeys.FirstOrDefault(w => w.DeviceId == device.DeviceId && w.Type == KeyType.Item);
                if (myIkWrap == null)
                    return ServiceResponse.Fail($"This device is not authorized for secret [blue]{namespaceName}::{key}[/]. Request access.");

                ik = _keyManager.UnwrapIKWithNK(vault.Name, ns.Name, secret.Key, myIkWrap, nk);
                ikId = myIkWrap.KeyId;
                keyVersion = myIkWrap.KeyVersion + 1;
            }

            // Encrypt value with IK
            var valueBytes = Encoding.UTF8.GetBytes(value);
            secret.Payload = _crypto.EncryptValue(valueBytes, ik);

            // Ensure our device has its IK wrap
            EnsureIKWrapForCurrentDevice(vault, ns, secret, ik, ikId, keyVersion);

            return ServiceResponse.Ok();
        }

        public ServiceResponse UnsetSecret(VaultModel vault, string namespaceName, string key)
        {
            var ns = vault.Namespaces.FirstOrDefault(n => n.Name == namespaceName);
            if (ns == null)
                return ServiceResponse.Fail($"Namespace [blue]{namespaceName}[/] not found in vault.");

            var removed = ns.Secrets.RemoveAll(s => s.Key == key) > 0;
            return removed
                ? ServiceResponse.Ok()
                : ServiceResponse.Fail($"Secret with key [blue]{namespaceName}::{key}[/] not found in namespace.");
        }

        // ---------------------------------------------------------------------
        // Export / Import plaintext
        // ---------------------------------------------------------------------

        public ServiceResponse<Dictionary<string, string>> ExportPlaintext(VaultModel vault, string namespaceName)
        {
            var ns = vault.Namespaces.FirstOrDefault(n => n.Name == namespaceName);
            if (ns == null)
                return ServiceResponse<Dictionary<string, string>>.Fail($"Namespace {namespaceName} not found in vault.");

            // Must have NK + IK wraps for this device to export
            _ = RequireNKForCurrentDevice(vault, ns);

            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            foreach (var secret in ns.Secrets)
            {
                try
                {
                    var ik = RequireIKForCurrentDevice(vault, ns, secret);
                    var plaintext = _crypto.DecryptValue(secret.Payload, ik);
                    result[secret.Key] = Encoding.UTF8.GetString(plaintext);
                }
                catch
                {
                    // Skip secrets we cannot unwrap on this device
                }
            }

            return ServiceResponse<Dictionary<string, string>>.Ok(result);
        }

        public ServiceResponse ImportPlaintext(VaultModel vault, IDictionary<string, string> newSecrets, string namespaceName)
        {
            var ns = vault.Namespaces.FirstOrDefault(n => n.Name == namespaceName);
            if (ns == null)
            {
                ns = new Namespace { Id = Guid.NewGuid(), Name = namespaceName, WrappedNamespaceKeys = new(), Secrets = new() };
                vault.Namespaces.Add(ns);
            }

            // Ensure we hold NK for this device (creates NK if namespace is new)
            _ = EnsureNKForCurrentDevice(vault, ns);

            // Delete keys not present in import
            ns.Secrets.RemoveAll(s => !newSecrets.ContainsKey(s.Key));

            // Add/update to match import
            foreach (var kvp in newSecrets)
            {
                var setResult = SetSecret(vault, namespaceName, kvp.Key, kvp.Value);
                if (setResult.IsFailure)
                {
                    AnsiConsole.MarkupLine($"[red]Failed to set secret [blue]{namespaceName}::{kvp.Key}[/]: {setResult.ErrorMessage}[/]");
                }
            }

            return ServiceResponse.Ok();
        }
    }
}
