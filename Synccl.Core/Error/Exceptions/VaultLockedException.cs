namespace Synccl.Core.Error.Exceptions
{
    public class VaultLockedException : Exception
    {
        public VaultLockedException(string vaultName)
            : base($"Vault '{vaultName}' could not be unlocked with the provided credentials.") { }
    }
}
