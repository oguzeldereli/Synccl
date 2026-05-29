namespace Synccl.Core.Error.Exceptions
{
    public class VaultNotFoundException : Exception
    {
        public VaultNotFoundException(string vaultName)
            : base($"Vault '{vaultName}' not found. Run 'synccl init' to create one.") { }
    }
}
