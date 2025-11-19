using Spectre.Console;
using Synccl.Cli.Config;
using Synccl.Cli.Helpers;
using Synccl.Cli.KeyWrapper;
using Synccl.Cli.Platform;
using Synccl.Core.Crypto;
using Synccl.Core.Device;
using Synccl.Core.Keys;
using Synccl.Core.Remote;
using Synccl.Core.Vault;
using Synccl.Core.VaultCrypto;
using System;
using System.Runtime.InteropServices;
using YamlDotNet.Serialization;

namespace Synccl.Cli.Composition
{
    public static class ServiceFactory
    {
        public static List<IRemoteStore> CreateRemotes(string root)
        {
            var vaultsService = CreateVaultService(root);
            if (vaultsService == null) return new();

            SyncclConfig config;

            try
            {
                config = ConfigLoader.Load();
            }
            catch
            {
                return new();
            }

            var r = config.Remotes;
            if (r == null) return new();

            var remotes = new List<IRemoteStore>();
            foreach (var remoteConfig in r)
            {
                if (remoteConfig.Type == "s3")
                {
                    remotes.Add(new S3RemoteStore(
                        remoteConfig.Bucket,
                        $"{remoteConfig.Prefix}/secrets.json",
                        remoteConfig.Region,
                        vaultsService,
                        remoteConfig.Profile
                    ));
                }
            }

            return remotes;
        }

        public static IRemoteStore? CreateRemote(string root, string name)
        {
            var vaultsService = CreateVaultService(root);
            if (vaultsService == null) return null;

            SyncclConfig config;
            config = ConfigLoader.Load(root);

            var r = config.Remotes;
            if (r == null) return null;

            var configByName = r.FirstOrDefault(rc => rc.Name == name);
            if (configByName != null)
            {
                if (configByName.Type == "s3")
                {
                    return new S3RemoteStore(
                        configByName.Bucket,
                        $"{configByName.Prefix}/secrets.json",
                        configByName.Region,
                        vaultsService,
                        configByName.Profile
                    );
                }
            }

            return null;
        }

        public static IVaultService CreateVaultService(string root)
        {
            var vaultPath = Path.Combine(root, ".synccl");
            var account = VaultAccountIdHelper.GetAccountId(root);
            if (account == null)
            {
                throw new InvalidOperationException("[red]Error:[/] Could not determine vault account ID. Is Synccl initialized?");
            }

            ISecureKeyWrapper? keyWrapper = null;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                keyWrapper = GetSecureKeyWrapper(root);

            var keychain = CreateKeychain(root, keyWrapper);
            var deviceKeys = new DeviceKeyService(keychain);
            var deviceManager = new DeviceManager(root, keychain);
            var keyManager = new DeviceVaultKeyManager(deviceManager, deviceKeys.GetOrCreate);
            var cryptoEngine = new VaultCryptoEngine();

            return new VaultService(vaultPath, deviceManager, keyManager, cryptoEngine);
        }

        public static IKeychain CreateKeychain(string root, ISecureKeyWrapper? wrapper)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && wrapper != null)
                return new WindowsKeychain(root, wrapper);
            
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) && wrapper != null)
                return new LinuxKeychain(wrapper);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                return new MacKeychain();

            if (wrapper == null)
                throw new PlatformNotSupportedException("Wrapper cannot be null for linux and windows machines.");

            throw new PlatformNotSupportedException("Unsupported OS for Synccl keychain integration");
        }

        public static ISecureKeyWrapper GetSecureKeyWrapper(string root)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                return new WindowsLinuxTPMKeyWrapper(root);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                throw new PlatformNotSupportedException("MacOS is not yet supported for Synccl keychain integration");

            throw new PlatformNotSupportedException("Unsupported OS for Synccl keychain integration");
        }
    }
}
