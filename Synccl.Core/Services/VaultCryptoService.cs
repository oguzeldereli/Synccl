using Sodium;
using Synccl.Core.Enums;
using Synccl.Core.Enums.KeyWrapping;
using Synccl.Core.Error.Exceptions;
using Synccl.Core.Interfaces;
using Synccl.Core.Interfaces.Security;
using Synccl.Core.Model;
using Synccl.Core.Model.EncryptedLocalVault;
using Synccl.Core.Model.LocalVault;
using Synccl.Core.Model.Security;
using Synccl.Core.Security;
using System.Security.Cryptography;
using System.Text;

namespace Synccl.Core.Services
{
    /// <summary>
    /// Provides all cryptographic operations for the vault:
    /// key generation, item encrypt/decrypt, full vault decrypt/re-encrypt,
    /// key rotation, and protect/unprotect.
    ///
    /// Key hierarchy
    ///   vault master key  (32 bytes)  ── wrapped by TPM (and optionally passphrase/pubkey)
    ///     └─ namespace key (32 bytes) ── wrapped by vault master key (ParentKey profile)
    ///           └─ item key (32 bytes) ── wrapped by namespace key (ParentKey profile)
    ///                 └─ item value  ── XChaCha20-Poly1305 encrypted with item key
    /// </summary>
    public sealed class VaultCryptoService : IVaultCryptoService
    {
        private readonly KeyWrapper _keyWrapper;
        private readonly ITPMManager _tpmManager;

        public VaultCryptoService(ITPMKeyWrapper tpmKeyWrapper, ITPMManager tpmManager)
        {
            _tpmManager = tpmManager ?? throw new ArgumentNullException(nameof(tpmManager));
            _keyWrapper = new KeyWrapper(tpmKeyWrapper, tpmManager);
        }

        // ------------------------------------------------------------------ //
        //  Key generation helpers
        // ------------------------------------------------------------------ //

        private static byte[] GenerateKey32() { var k = new byte[32]; RandomNumberGenerator.Fill(k); return k; }

        // ------------------------------------------------------------------ //
        //  Vault initialisation
        // ------------------------------------------------------------------ //

        public EncryptedLocalVault InitialiseVault(string vaultName, string defaultNamespaceName)
        {
            var vaultKeyId = Guid.NewGuid();
            var vaultKey = GenerateKey32();

            try
            {
                // Wrap vault master key with TPM.
                var vaultKeyWrap = _keyWrapper.Wrap(
                    KeyWrappingProfile.TpmAes256,
                    vaultKeyId,
                    Guid.Empty,
                    vaultKey,
                    Array.Empty<byte>(), // TPM profile ignores wrappingMaterial
                    $"vault:{vaultName}:master");

                // Create default namespace key, wrapped by vault master key.
                var nsKeyId = Guid.NewGuid();
                var nsKey = GenerateKey32();

                try
                {
                    var nsKeyWrap = _keyWrapper.Wrap(
                        KeyWrappingProfile.ParentKeyXChaCha20Poly1305,
                        nsKeyId,
                        vaultKeyId,
                        nsKey,
                        vaultKey,
                        $"vault:{vaultName}:ns:{defaultNamespaceName}");

                    var defaultNs = EncryptedLocalNamespace.CreateNew(defaultNamespaceName, [nsKeyWrap]);

                    var vault = EncryptedLocalVault.Reconstruct(
                        Guid.NewGuid(),
                        vaultName,
                        defaultNamespaceName,
                        1,
                        EncryptedLocalVaultAccessMode.MountedDeviceBound,
                        [vaultKeyWrap],
                        [defaultNs]);

                    return vault;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(nsKey);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
            }
        }

        // ------------------------------------------------------------------ //
        //  Key unwrap helpers
        // ------------------------------------------------------------------ //

        private byte[] UnwrapVaultKey(EncryptedLocalVault vault, UnlockContext unlock)
        {
            var wrap = SelectWrap(vault.WrappedVaultKeys, unlock)
                ?? throw new VaultLockedException(vault.Name);

            return _keyWrapper.Unwrap(wrap, GetUnwrappingMaterial(unlock, wrap));
        }

        private byte[] UnwrapNamespaceKey(
            EncryptedLocalVault vault,
            EncryptedLocalNamespace ns,
            byte[] vaultKey)
        {
            // Namespace key is always wrapped by the vault parent key.
            var wrap = ns.WrappedNamespaceKeys.FirstOrDefault()
                ?? throw new InvalidOperationException($"Namespace '{ns.Name}' has no key wraps.");
            return _keyWrapper.Unwrap(wrap, vaultKey);
        }

        private byte[] UnwrapItemKey(EncryptedLocalItem item, byte[] nsKey)
        {
            var wrap = item.WrappedItemKeys.FirstOrDefault()
                ?? throw new InvalidOperationException($"Item '{item.Key}' has no key wraps.");
            return _keyWrapper.Unwrap(wrap, nsKey);
        }

        private static KeyWrap? SelectWrap(IReadOnlyList<KeyWrap> wraps, UnlockContext unlock)
        {
            if (unlock.IsTpm)
                return wraps.FirstOrDefault(w =>
                    w.Profile == KeyWrappingProfile.TpmAes256 ||
                    w.Profile == KeyWrappingProfile.TpmAes128);

            if (unlock.IsPassphrase)
                return wraps.FirstOrDefault(w =>
                    w.Profile == KeyWrappingProfile.PassphraseArgon2IdXChaCha20Poly1305);

            if (unlock.IsPublicKey)
                return wraps.FirstOrDefault(w =>
                    w.Profile == KeyWrappingProfile.PublicKeyX25519HkdfXChaCha20Poly1305);

            return null;
        }

        private static byte[] GetUnwrappingMaterial(UnlockContext unlock, KeyWrap wrap)
        {
            if (unlock.IsTpm) return Array.Empty<byte>(); // TPM path ignores this
            if (unlock.IsPassphrase) return unlock.PassphraseBytes!;
            if (unlock.IsPublicKey) return unlock.PrivateKeyBytes!;
            return Array.Empty<byte>();
        }

        // ------------------------------------------------------------------ //
        //  Item encryption / decryption
        // ------------------------------------------------------------------ //

        private EncryptedLocalItem EncryptItem(
            string key, string value, Guid nsKeyId, byte[] nsKey, string vaultName, string nsName)
        {
            var itemKeyId = Guid.NewGuid();
            var itemKey = GenerateKey32();

            try
            {
                var itemKeyWrap = _keyWrapper.Wrap(
                    KeyWrappingProfile.ParentKeyXChaCha20Poly1305,
                    itemKeyId,
                    nsKeyId,
                    itemKey,
                    nsKey,
                    $"vault:{vaultName}:ns:{nsName}:item:{key}");

                var payload = EncryptValue(value, itemKeyId, itemKey, key, nsName, vaultName);
                return EncryptedLocalItem.Create(key, payload, [itemKeyWrap]);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(itemKey);
            }
        }

        private static EncryptedDataBlob EncryptValue(
            string value, Guid itemKeyId, byte[] itemKey,
            string itemKeyName, string nsName, string vaultName)
        {
            var plaintext = Encoding.UTF8.GetBytes(value);
            var nonce = new byte[24];
            RandomNumberGenerator.Fill(nonce);

            var aadObj = new { Vault = vaultName, Namespace = nsName, Key = itemKeyName, KeyId = itemKeyId };
            var aad = Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(aadObj));

            var ciphertext = SecretAeadXChaCha20Poly1305.Encrypt(plaintext, nonce, itemKey, aad);

            return EncryptedDataBlob.Create(DataEncryptionAlgorithm.XChaCha20Poly1305, ciphertext, nonce, aad, itemKeyId);
        }

        private string DecryptItem(EncryptedLocalItem item, byte[] itemKey)
        {
            var blob = item.Payload;
            var plaintext = SecretAeadXChaCha20Poly1305.Decrypt(blob.Ciphertext, blob.Nonce, itemKey, blob.Aad);
            return Encoding.UTF8.GetString(plaintext);
        }

        // ------------------------------------------------------------------ //
        //  Public single-item operations
        // ------------------------------------------------------------------ //

        public void SetItem(
            EncryptedLocalVault vault, string namespaceName, string key, string value, UnlockContext unlock)
        {
            var vaultKey = UnwrapVaultKey(vault, unlock);
            try
            {
                var ns = vault.GetNamespace(namespaceName);
                var nsKey = UnwrapNamespaceKey(vault, ns, vaultKey);
                var nsKeyId = ns.WrappedNamespaceKeys[0].WrappedKeyId;

                try
                {
                    var item = EncryptItem(key, value, nsKeyId, nsKey, vault.Name, namespaceName);
                    // Get live namespace copy, mutate, then replace in vault.
                    ns.SetOrReplaceItem(item);
                    vault.ReplaceNamespace(ns);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(nsKey);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
            }
        }

        public string GetItem(
            EncryptedLocalVault vault, string namespaceName, string key, UnlockContext unlock)
        {
            var vaultKey = UnwrapVaultKey(vault, unlock);
            try
            {
                var ns = vault.GetNamespace(namespaceName);
                var nsKey = UnwrapNamespaceKey(vault, ns, vaultKey);
                try
                {
                    var item = ns.GetItem(key);
                    var itemKey = UnwrapItemKey(item, nsKey);
                    try
                    {
                        return DecryptItem(item, itemKey);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(itemKey);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(nsKey);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
            }
        }

        public void RemoveItem(EncryptedLocalVault vault, string namespaceName, string key)
        {
            var ns = vault.GetNamespace(namespaceName);
            ns.RemoveItem(key);
            vault.ReplaceNamespace(ns);
        }

        // ------------------------------------------------------------------ //
        //  Full vault decrypt / re-encrypt
        // ------------------------------------------------------------------ //

        public LocalVault DecryptVault(EncryptedLocalVault vault, UnlockContext unlock)
        {
            var vaultKey = UnwrapVaultKey(vault, unlock);
            try
            {
                var local = new LocalVault(vault.Id, vault.Version, vault.Name, vault.DefaultNamespaceName);

                foreach (var encNs in vault.Namespaces)
                {
                    if (encNs.Name != vault.DefaultNamespaceName)
                        local.AddNamespace(encNs.Name);

                    var nsKey = UnwrapNamespaceKey(vault, encNs, vaultKey);
                    try
                    {
                        foreach (var item in encNs.EncryptedItems)
                        {
                            var itemKey = UnwrapItemKey(item, nsKey);
                            try
                            {
                                var value = DecryptItem(item, itemKey);
                                local.SetItem(item.Key, value, encNs.Name);
                            }
                            finally
                            {
                                CryptographicOperations.ZeroMemory(itemKey);
                            }
                        }
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(nsKey);
                    }
                }

                return local;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
            }
        }

        public EncryptedLocalVault EncryptVault(
            LocalVault localVault, EncryptedLocalVault existingEncrypted, UnlockContext unlock)
        {
            var vaultKey = UnwrapVaultKey(existingEncrypted, unlock);
            try
            {
                var newNamespaces = new List<EncryptedLocalNamespace>();

                foreach (var nsName in localVault.GetNamespaceSnapshots().Keys)
                {
                    // Reuse existing namespace key wraps if the namespace already exists.
                    EncryptedLocalNamespace? existingNs = null;
                    if (existingEncrypted.ContainsNamespace(nsName))
                        existingNs = existingEncrypted.GetNamespace(nsName);

                    EncryptedLocalNamespace encNs;
                    byte[] nsKey;
                    Guid nsKeyId;

                    if (existingNs is not null)
                    {
                        nsKey = UnwrapNamespaceKey(existingEncrypted, existingNs, vaultKey);
                        nsKeyId = existingNs.WrappedNamespaceKeys[0].WrappedKeyId;
                        encNs = EncryptedLocalNamespace.Reconstruct(
                            existingNs.Id, nsName,
                            existingNs.WrappedNamespaceKeys, []);
                    }
                    else
                    {
                        nsKeyId = Guid.NewGuid();
                        nsKey = GenerateKey32();
                        var nsKeyWrap = _keyWrapper.Wrap(
                            KeyWrappingProfile.ParentKeyXChaCha20Poly1305,
                            nsKeyId,
                            existingEncrypted.WrappedVaultKeys[0].WrappedKeyId,
                            nsKey,
                            vaultKey,
                            $"vault:{localVault.Name}:ns:{nsName}");
                        encNs = EncryptedLocalNamespace.CreateNew(nsName, [nsKeyWrap]);
                    }

                    try
                    {
                        var snapshot = localVault.GetNamespaceSnapshot(nsName);
                        foreach (var (itemKey, item) in snapshot.GetItems())
                        {
                            var encItem = EncryptItem(itemKey, item.Value, nsKeyId, nsKey, localVault.Name, nsName);
                            encNs.SetOrReplaceItem(encItem);
                        }
                    }
                    finally
                    {
                        if (existingNs is null) CryptographicOperations.ZeroMemory(nsKey);
                        else CryptographicOperations.ZeroMemory(nsKey);
                    }

                    newNamespaces.Add(encNs);
                }

                var updated = EncryptedLocalVault.Reconstruct(
                    existingEncrypted.Id,
                    existingEncrypted.Name,
                    existingEncrypted.DefaultNamespaceName,
                    existingEncrypted.Version,
                    existingEncrypted.AccessMode,
                    existingEncrypted.WrappedVaultKeys,
                    newNamespaces);

                return updated;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(vaultKey);
            }
        }

        // ------------------------------------------------------------------ //
        //  Key rotation
        // ------------------------------------------------------------------ //

        public EncryptedLocalVault RotateVaultKey(
            EncryptedLocalVault vault, UnlockContext unlock, bool rotateAll)
        {
            var oldVaultKey = UnwrapVaultKey(vault, unlock);
            try
            {
                var newVaultKeyId = Guid.NewGuid();
                var newVaultKey = GenerateKey32();
                try
                {
                    var newVaultWrap = _keyWrapper.Wrap(
                        KeyWrappingProfile.TpmAes256,
                        newVaultKeyId,
                        Guid.Empty,
                        newVaultKey,
                        Array.Empty<byte>(),
                        $"vault:{vault.Name}:master");

                    var newNamespaces = new List<EncryptedLocalNamespace>();
                    foreach (var encNs in vault.Namespaces)
                    {
                        var oldNsKey = UnwrapNamespaceKey(vault, encNs, oldVaultKey);
                        try
                        {
                            var nsKeyId = rotateAll ? Guid.NewGuid() : encNs.WrappedNamespaceKeys[0].WrappedKeyId;
                            var nsKey = rotateAll ? GenerateKey32() : oldNsKey.ToArray();
                            try
                            {
                                var newNsWrap = _keyWrapper.Wrap(
                                    KeyWrappingProfile.ParentKeyXChaCha20Poly1305,
                                    nsKeyId,
                                    newVaultKeyId,
                                    nsKey,
                                    newVaultKey,
                                    $"vault:{vault.Name}:ns:{encNs.Name}");

                                var newNs = EncryptedLocalNamespace.Reconstruct(
                                    encNs.Id, encNs.Name, [newNsWrap], []);

                                foreach (var item in encNs.EncryptedItems)
                                {
                                    if (rotateAll)
                                    {
                                        var oldItemKey = UnwrapItemKey(item, oldNsKey);
                                        try
                                        {
                                            var plaintext = DecryptItem(item, oldItemKey);
                                            var newItem = EncryptItem(item.Key, plaintext, nsKeyId, nsKey, vault.Name, encNs.Name);
                                            newNs.SetOrReplaceItem(newItem);
                                        }
                                        finally { CryptographicOperations.ZeroMemory(oldItemKey); }
                                    }
                                    else
                                    {
                                        // Re-wrap item key with same item key but new parent.
                                        var oldItemKey = UnwrapItemKey(item, oldNsKey);
                                        try
                                        {
                                            var itemKeyId = item.WrappedItemKeys[0].WrappedKeyId;
                                            var newItemWrap = _keyWrapper.Wrap(
                                                KeyWrappingProfile.ParentKeyXChaCha20Poly1305,
                                                itemKeyId, nsKeyId, oldItemKey, nsKey,
                                                $"vault:{vault.Name}:ns:{encNs.Name}:item:{item.Key}");
                                            var newItem = EncryptedLocalItem.Reconstruct(
                                                item.Id, item.Key, item.Payload, [newItemWrap]);
                                            newNs.SetOrReplaceItem(newItem);
                                        }
                                        finally { CryptographicOperations.ZeroMemory(oldItemKey); }
                                    }
                                }
                                newNamespaces.Add(newNs);
                            }
                            finally { CryptographicOperations.ZeroMemory(nsKey); }
                        }
                        finally { CryptographicOperations.ZeroMemory(oldNsKey); }
                    }

                    var rotated = EncryptedLocalVault.Reconstruct(
                        vault.Id, vault.Name, vault.DefaultNamespaceName,
                        vault.Version, vault.AccessMode,
                        [newVaultWrap], newNamespaces);
                    rotated.IncrementVersion();
                    return rotated;
                }
                finally { CryptographicOperations.ZeroMemory(newVaultKey); }
            }
            finally { CryptographicOperations.ZeroMemory(oldVaultKey); }
        }

        public void RotateNamespaceKey(
            EncryptedLocalVault vault, string namespaceName, UnlockContext unlock, bool rotateAll)
        {
            var vaultKey = UnwrapVaultKey(vault, unlock);
            try
            {
                var ns = vault.GetNamespace(namespaceName);
                var oldNsKey = UnwrapNamespaceKey(vault, ns, vaultKey);
                try
                {
                    var vaultKeyId = vault.WrappedVaultKeys[0].WrappedKeyId;
                    var newNsKeyId = Guid.NewGuid();
                    var newNsKey = GenerateKey32();
                    try
                    {
                        var newNsWrap = _keyWrapper.Wrap(
                            KeyWrappingProfile.ParentKeyXChaCha20Poly1305,
                            newNsKeyId, vaultKeyId, newNsKey, vaultKey,
                            $"vault:{vault.Name}:ns:{namespaceName}");
                        ns.ReplaceKeyWraps([newNsWrap]);

                        foreach (var item in ns.EncryptedItems.ToList())
                        {
                            var oldItemKey = UnwrapItemKey(item, oldNsKey);
                            try
                            {
                                if (rotateAll)
                                {
                                    var plaintext = DecryptItem(item, oldItemKey);
                                    var newItem = EncryptItem(item.Key, plaintext, newNsKeyId, newNsKey, vault.Name, namespaceName);
                                    ns.SetOrReplaceItem(newItem);
                                }
                                else
                                {
                                    var itemKeyId = item.WrappedItemKeys[0].WrappedKeyId;
                                    var newItemWrap = _keyWrapper.Wrap(
                                        KeyWrappingProfile.ParentKeyXChaCha20Poly1305,
                                        itemKeyId, newNsKeyId, oldItemKey, newNsKey,
                                        $"vault:{vault.Name}:ns:{namespaceName}:item:{item.Key}");
                                    var newItem = EncryptedLocalItem.Reconstruct(item.Id, item.Key, item.Payload, [newItemWrap]);
                                    ns.SetOrReplaceItem(newItem);
                                }
                            }
                            finally { CryptographicOperations.ZeroMemory(oldItemKey); }
                        }

                        vault.ReplaceNamespace(ns);
                    }
                    finally { CryptographicOperations.ZeroMemory(newNsKey); }
                }
                finally { CryptographicOperations.ZeroMemory(oldNsKey); }
            }
            finally { CryptographicOperations.ZeroMemory(vaultKey); }
        }

        public void RotateItemKey(
            EncryptedLocalVault vault, string namespaceName, string itemKey, UnlockContext unlock)
        {
            var vaultKey = UnwrapVaultKey(vault, unlock);
            try
            {
                var ns = vault.GetNamespace(namespaceName);
                var nsKey = UnwrapNamespaceKey(vault, ns, vaultKey);
                var nsKeyId = ns.WrappedNamespaceKeys[0].WrappedKeyId;
                try
                {
                    var item = ns.GetItem(itemKey);
                    var oldItemKey = UnwrapItemKey(item, nsKey);
                    try
                    {
                        var plaintext = DecryptItem(item, oldItemKey);
                        var newItem = EncryptItem(itemKey, plaintext, nsKeyId, nsKey, vault.Name, namespaceName);
                        ns.SetOrReplaceItem(newItem);
                        vault.ReplaceNamespace(ns);
                    }
                    finally { CryptographicOperations.ZeroMemory(oldItemKey); }
                }
                finally { CryptographicOperations.ZeroMemory(nsKey); }
            }
            finally { CryptographicOperations.ZeroMemory(vaultKey); }
        }

        // ------------------------------------------------------------------ //
        //  Protect / Unprotect
        // ------------------------------------------------------------------ //

        public void Protect(EncryptedLocalVault vault, UnlockContext unlock, UnlockContext newProtection)
        {
            var vaultKey = UnwrapVaultKey(vault, unlock);
            try
            {
                var vaultKeyId = vault.WrappedVaultKeys[0].WrappedKeyId;
                KeyWrap newWrap;

                if (newProtection.IsPassphrase)
                {
                    newWrap = _keyWrapper.Wrap(
                        KeyWrappingProfile.PassphraseArgon2IdXChaCha20Poly1305,
                        vaultKeyId, Guid.Empty, vaultKey,
                        newProtection.PassphraseBytes!,
                        $"vault:{vault.Name}:passphrase");
                    SetAccessMode(vault, EncryptedLocalVaultAccessMode.MountedDeviceBoundPassphraseProtected);
                }
                else if (newProtection.IsPublicKey)
                {
                    newWrap = _keyWrapper.Wrap(
                        KeyWrappingProfile.PublicKeyX25519HkdfXChaCha20Poly1305,
                        vaultKeyId, Guid.Empty, vaultKey,
                        newProtection.PrivateKeyBytes!,
                        $"vault:{vault.Name}:pubkey");
                    SetAccessMode(vault, EncryptedLocalVaultAccessMode.MountedDeviceBoundPublicKeyProtected);
                }
                else
                {
                    throw new ArgumentException("New protection must specify passphrase or public key.");
                }

                vault.AddVaultKeyWrap(newWrap);
            }
            finally { CryptographicOperations.ZeroMemory(vaultKey); }
        }

        public void Unprotect(EncryptedLocalVault vault, UnlockContext currentUnlock)
        {
            // Ensure the vault can actually be unlocked.
            var vaultKey = UnwrapVaultKey(vault, currentUnlock);
            CryptographicOperations.ZeroMemory(vaultKey);

            // Remove non-TPM wraps.
            var toRemove = vault.WrappedVaultKeys
                .Where(w => w.Profile != KeyWrappingProfile.TpmAes256 &&
                             w.Profile != KeyWrappingProfile.TpmAes128)
                .Select(w => w.Id)
                .ToList();

            foreach (var id in toRemove)
                vault.RemoveVaultKeyWrap(id);

            SetAccessMode(vault, EncryptedLocalVaultAccessMode.MountedDeviceBound);
        }

        public void SetAccessMode(EncryptedLocalVault vault, EncryptedLocalVaultAccessMode mode)
            => vault.SetAccessMode(mode);

        // ------------------------------------------------------------------ //
        //  Internal surface used by VaultService
        // ------------------------------------------------------------------ //

        internal KeyWrapper KeyWrapper => _keyWrapper;

        internal byte[] UnwrapVaultKeyPublic(EncryptedLocalVault vault, UnlockContext unlock)
            => UnwrapVaultKey(vault, unlock);
    }
}
