namespace Synccl.Core.Error.Exceptions
{
    public class VaultAlreadyExistsException : Exception
    {
        public VaultAlreadyExistsException(string vaultName)
            : base($"A vault named '{vaultName}' already exists.") { }
    }
}
