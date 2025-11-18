using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Helpers
{
    public class VaultAccountIdHelper
    {
        public static string? GetAccountId(string root)
        {
            var vaultIdPath = Path.Combine(root, ".synccl", "id");
            string? vaultId = File.Exists(vaultIdPath)
                ? File.ReadAllText(vaultIdPath).Trim()
                : null;

            if (vaultId == null)
                return null;

            var deviceName = Environment.MachineName;
            var userName = Environment.UserName;
            return $"{userName}@{deviceName}-{vaultId}";
        }
    }
}
