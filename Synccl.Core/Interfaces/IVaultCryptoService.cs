using Synccl.Core.Enums;
using Synccl.Core.Model;
using Synccl.Core.Model.EncryptedLocalVault;
using Synccl.Core.Model.LocalVault;

namespace Synccl.Core.Interfaces
{
    /// <summary>
    /// Handles all cryptographic operations on vault data.
    /// </summary>
    public interface IVaultCryptoService
    {
        // ---- Vault initialisation ----

        /// <summary>
        /// Generate a fresh vault master key and wrap it with the device TPM,
        /// creating the initial key-wrap set for the vault and its default namespace.
        /// </summary>
        EncryptedLocalVault InitialiseVault(string vaultName, string defaultNamespaceName);

        // ---- Single-item operations (no full vault decrypt needed) ----

        /// <summary>
        /// Encrypt a plain-text value and store it as a new/replaced item in
        /// the encrypted namespace. The namespace key is unwrapped on the fly.
        /// </summary>
        void SetItem(
            EncryptedLocalVault vault,
            string namespaceName,
            string key,
            string value,
            UnlockContext unlock);

        /// <summary>
        /// Decrypt and return the value for a single item.
        /// </summary>
        string GetItem(
            EncryptedLocalVault vault,
            string namespaceName,
            string key,
            UnlockContext unlock);

        /// <summary>Remove an item from the encrypted namespace.</summary>
        void RemoveItem(
            EncryptedLocalVault vault,
            string namespaceName,
            string key);

        // ---- Full vault decrypt/re-encrypt ----

        /// <summary>
        /// Fully decrypt a vault to a <see cref="LocalVault"/> for bulk operations.
        /// </summary>
        LocalVault DecryptVault(EncryptedLocalVault vault, UnlockContext unlock);

        /// <summary>
        /// Re-encrypt a <see cref="LocalVault"/> into an updated <see cref="EncryptedLocalVault"/>,
        /// preserving the existing key wraps.
        /// </summary>
        EncryptedLocalVault EncryptVault(
            LocalVault localVault,
            EncryptedLocalVault existingEncrypted,
            UnlockContext unlock);

        // ---- Key rotation ----

        /// <summary>Rotate the vault master key (and optionally all namespace/item keys).</summary>
        EncryptedLocalVault RotateVaultKey(EncryptedLocalVault vault, UnlockContext unlock, bool rotateAll);

        /// <summary>Rotate a namespace key (and optionally all item keys inside it).</summary>
        void RotateNamespaceKey(
            EncryptedLocalVault vault,
            string namespaceName,
            UnlockContext unlock,
            bool rotateAll);

        /// <summary>Rotate the key for a single item.</summary>
        void RotateItemKey(
            EncryptedLocalVault vault,
            string namespaceName,
            string itemKey,
            UnlockContext unlock);

        // ---- Mount / Unmount (key transport) ----

        /// <summary>
        /// Unmount: unwrap the vault master key via the current TPM, add a passphrase-Argon2id
        /// or public-key wrap, and REMOVE the TPM wrap. The vault file becomes portable and
        /// machine-independent.  AccessMode is set to the appropriate Unmounted* value.
        /// </summary>
        EncryptedLocalVault UnmountVault(EncryptedLocalVault vault, UnlockContext transportProtection);

        /// <summary>
        /// Mount: unwrap the vault master key via the passphrase or public-key wrap, add a
        /// TPM wrap for THIS machine, and REMOVE the passphrase/pubkey wraps.  The vault
        /// becomes device-bound and AccessMode is set to MountedDeviceBound.
        /// </summary>
        EncryptedLocalVault MountVault(EncryptedLocalVault vault, UnlockContext transportUnlock);

        // ---- Access mode ----
        void SetAccessMode(EncryptedLocalVault vault, EncryptedLocalVaultAccessMode mode);
    }
}
