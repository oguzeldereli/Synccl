using Synccl.Core.Enums;
using Synccl.Core.Enums.KeyWrapping;
using Synccl.Core.Model;
using Synccl.Core.Model.EncryptedLocalVault;
using Synccl.Core.Model.Security;
using Synccl.Core.Persistence.Dto;

namespace Synccl.Core.Persistence
{
    /// <summary>
    /// Converts between persistence DTOs (plain JSON-friendly objects) and
    /// the rich domain model. All byte arrays are stored as Base64 strings.
    /// </summary>
    public static class VaultMapper
    {
        // ------------------------------------------------------------------ //
        //  DTO → Domain
        // ------------------------------------------------------------------ //

        public static EncryptedLocalVault ToDomain(EncryptedLocalVaultDto dto)
        {
            var accessMode = Enum.Parse<EncryptedLocalVaultAccessMode>(dto.AccessMode);

            // We need to build the vault by reflection on the private ctor because
            // CreateNew doesn't accept an explicit ID. Use the reconstruction path.
            var namespaces = dto.Namespaces.Select(ToNamespace).ToList();
            var keyWraps = dto.WrappedVaultKeys.Select(ToKeyWrap).ToList();

            return EncryptedLocalVault.Reconstruct(
                dto.Id,
                dto.Name,
                dto.DefaultNamespaceName,
                dto.Version,
                accessMode,
                keyWraps,
                namespaces);
        }

        public static VaultInfo ToVaultInfo(EncryptedLocalVaultDto dto, string filePath)
        {
            return new VaultInfo
            {
                Id = dto.Id,
                Name = dto.Name,
                FilePath = filePath,
                Version = dto.Version,
                AccessMode = dto.AccessMode,
                DefaultNamespaceName = dto.DefaultNamespaceName,
                NamespaceNames = dto.Namespaces.Select(n => n.Name).ToList()
            };
        }

        private static EncryptedLocalNamespace ToNamespace(EncryptedLocalNamespaceDto dto)
        {
            var wraps = dto.WrappedNamespaceKeys.Select(ToKeyWrap).ToList();
            var items = dto.Items.Select(ToItem).ToList();
            return EncryptedLocalNamespace.Reconstruct(dto.Id, dto.Name, wraps, items);
        }

        private static EncryptedLocalItem ToItem(EncryptedLocalItemDto dto)
        {
            var payload = ToBlob(dto.Payload);
            var wraps = dto.WrappedItemKeys.Select(ToKeyWrap).ToList();
            return EncryptedLocalItem.Reconstruct(dto.Id, dto.Key, payload, wraps);
        }

        private static EncryptedDataBlob ToBlob(EncryptedDataBlobDto dto)
        {
            return EncryptedDataBlob.Create(
                Enum.Parse<DataEncryptionAlgorithm>(dto.Algorithm),
                Convert.FromBase64String(dto.Ciphertext),
                Convert.FromBase64String(dto.Nonce),
                Convert.FromBase64String(dto.Aad),
                dto.EncryptedBy);
        }

        private static KeyWrap ToKeyWrap(KeyWrapDto dto)
        {
            var profile = Enum.Parse<KeyWrappingProfile>(dto.Profile);
            return profile switch
            {
                KeyWrappingProfile.TpmAes128 => KeyWrap.CreateTpmAes128(
                    dto.WrappedKeyId,
                    Convert.FromBase64String(dto.WrappedKey),
                    Convert.FromBase64String(dto.TpmEndorsementKeyHash!),
                    ToTpmBlob(dto.TpmKeyBlob!)),

                KeyWrappingProfile.TpmAes256 => KeyWrap.CreateTpmAes256(
                    dto.WrappedKeyId,
                    Convert.FromBase64String(dto.WrappedKey),
                    Convert.FromBase64String(dto.TpmEndorsementKeyHash!),
                    ToTpmBlob(dto.TpmKeyBlob!)),

                KeyWrappingProfile.PassphraseArgon2IdXChaCha20Poly1305 => KeyWrap.CreatePassphraseArgon2IdXChaCha20Poly1305(
                    dto.WrappedKeyId,
                    Convert.FromBase64String(dto.WrappedKey),
                    Convert.FromBase64String(dto.Nonce!),
                    Convert.FromBase64String(dto.Aad!),
                    Convert.FromBase64String(dto.Salt!),
                    dto.Argon2MemoryKiB!.Value,
                    dto.Argon2Iterations!.Value),

                KeyWrappingProfile.PublicKeyX25519HkdfXChaCha20Poly1305 => KeyWrap.CreatePublicKeyX25519HkdfXChaCha20Poly1305(
                    dto.WrappedKeyId,
                    Convert.FromBase64String(dto.WrappedKey),
                    Convert.FromBase64String(dto.Nonce!),
                    Convert.FromBase64String(dto.Aad!),
                    Convert.FromBase64String(dto.Salt!),
                    Convert.FromBase64String(dto.Info!),
                    Convert.FromBase64String(dto.EphemeralPublicKey!)),

                KeyWrappingProfile.ParentKeyXChaCha20Poly1305 => KeyWrap.CreateParentKeyXChaCha20Poly1305(
                    dto.WrappedKeyId,
                    dto.WrappingKeyId!.Value,
                    Convert.FromBase64String(dto.WrappedKey),
                    Convert.FromBase64String(dto.Nonce!),
                    Convert.FromBase64String(dto.Aad!)),

                _ => throw new NotSupportedException($"Unknown key wrapping profile: {profile}")
            };
        }

        private static TPMKeyBlob ToTpmBlob(TpmKeyBlobDto dto)
        {
            return TPMKeyBlob.Create(
                Convert.FromBase64String(dto.Ciphertext),
                Convert.FromBase64String(dto.Iv),
                Convert.FromBase64String(dto.TpmPublicBlob),
                Convert.FromBase64String(dto.TpmPrivateBlob),
                Enum.Parse<KeyWrappingEncryptionAlgorithm>(dto.Algorithm));
        }

        // ------------------------------------------------------------------ //
        //  Domain → DTO
        // ------------------------------------------------------------------ //

        public static EncryptedLocalVaultDto ToDto(EncryptedLocalVault vault)
        {
            return new EncryptedLocalVaultDto
            {
                SchemaVersion = 1,
                Id = vault.Id,
                Name = vault.Name,
                Version = vault.Version,
                DefaultNamespaceName = vault.DefaultNamespaceName,
                AccessMode = vault.AccessMode.ToString(),
                WrappedVaultKeys = vault.WrappedVaultKeys.Select(ToDto).ToList(),
                Namespaces = vault.Namespaces.Select(ToDto).ToList()
            };
        }

        private static EncryptedLocalNamespaceDto ToDto(EncryptedLocalNamespace ns)
        {
            return new EncryptedLocalNamespaceDto
            {
                Id = ns.Id,
                Name = ns.Name,
                WrappedNamespaceKeys = ns.WrappedNamespaceKeys.Select(ToDto).ToList(),
                Items = ns.EncryptedItems.Select(ToDto).ToList()
            };
        }

        private static EncryptedLocalItemDto ToDto(EncryptedLocalItem item)
        {
            return new EncryptedLocalItemDto
            {
                Id = item.Id,
                Key = item.Key,
                Payload = ToDto(item.Payload),
                WrappedItemKeys = item.WrappedItemKeys.Select(ToDto).ToList()
            };
        }

        private static EncryptedDataBlobDto ToDto(EncryptedDataBlob blob)
        {
            return new EncryptedDataBlobDto
            {
                Algorithm = blob.Algorithm.ToString(),
                Ciphertext = Convert.ToBase64String(blob.Ciphertext),
                Nonce = Convert.ToBase64String(blob.Nonce),
                Aad = Convert.ToBase64String(blob.Aad),
                EncryptedBy = blob.EncryptedBy
            };
        }

        private static KeyWrapDto ToDto(KeyWrap wrap)
        {
            var dto = new KeyWrapDto
            {
                Id = wrap.Id,
                WrappedKeyId = wrap.WrappedKeyId,
                WrappingKeyId = wrap.WrappingKeyId,
                Profile = wrap.Profile.ToString(),
                CreatedAtUtc = wrap.CreatedAtUtc,
                WrappedKey = Convert.ToBase64String(wrap.WrappedKey)
            };

            if (wrap.Nonce is not null) dto.Nonce = Convert.ToBase64String(wrap.Nonce);
            if (wrap.Aad is not null) dto.Aad = Convert.ToBase64String(wrap.Aad);
            if (wrap.Salt is not null) dto.Salt = Convert.ToBase64String(wrap.Salt);
            if (wrap.Info is not null) dto.Info = Convert.ToBase64String(wrap.Info);
            if (wrap.EphemeralPublicKey is not null) dto.EphemeralPublicKey = Convert.ToBase64String(wrap.EphemeralPublicKey);
            if (wrap.TPMEndorsementKeyHash is not null) dto.TpmEndorsementKeyHash = Convert.ToBase64String(wrap.TPMEndorsementKeyHash);
            if (wrap.TPMKeyBlob is not null) dto.TpmKeyBlob = ToDto(wrap.TPMKeyBlob);
            if (wrap.Argon2MemoryKiB.HasValue) dto.Argon2MemoryKiB = wrap.Argon2MemoryKiB;
            if (wrap.Argon2Iterations.HasValue) dto.Argon2Iterations = wrap.Argon2Iterations;

            return dto;
        }

        private static TpmKeyBlobDto ToDto(TPMKeyBlob blob)
        {
            return new TpmKeyBlobDto
            {
                Ciphertext = Convert.ToBase64String(blob.Ciphertext),
                Iv = Convert.ToBase64String(blob.Iv),
                TpmPublicBlob = Convert.ToBase64String(blob.TpmPublicBlob),
                TpmPrivateBlob = Convert.ToBase64String(blob.TpmPrivateBlob),
                Algorithm = blob.Algorithm.ToString()
            };
        }
    }
}
