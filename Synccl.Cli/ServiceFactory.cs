using Synccl.Cli.Security;
using Synccl.Core.Interfaces;
using Synccl.Core.Persistence;
using Synccl.Core.Services;

namespace Synccl.Cli
{
    /// <summary>Bootstraps and owns the singleton IVaultService for the CLI process.</summary>
    internal static class ServiceFactory
    {
        private static IVaultService? _instance;

        internal static IVaultService Create()
        {
            if (_instance is not null) return _instance;

            var (tpmWrapper, tpmManager) = PlatformTpmFactory.Create();
            var cryptoService = new VaultCryptoService(tpmWrapper, tpmManager);
            var vaultStore = new VaultStore();
            _instance = new VaultService(vaultStore, cryptoService);
            return _instance;
        }
    }
}
