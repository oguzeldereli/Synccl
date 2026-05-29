using Spectre.Console;
using Synccl.Core.Model;
using System.Text;

namespace Synccl.Cli
{
    /// <summary>Shared CLI utilities: argument parsing, unlock context prompting.</summary>
    internal static class CliHelpers
    {
        // ------------------------------------------------------------------ //
        //  vault:ns:key parsing
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Parses a "vault:ns:key" triple with defaults applied.
        /// </summary>
        internal static (string Vault, string Ns, string Key) ParseVaultNsKey(
            string raw,
            string defaultVault = "default",
            string defaultNs = "default")
        {
            var parts = raw.Split(':', 3);
            return parts.Length switch
            {
                3 => (parts[0], parts[1], parts[2]),
                2 => (defaultVault, parts[0], parts[1]),
                1 => (defaultVault, defaultNs, parts[0]),
                _ => throw new ArgumentException($"Invalid vault:ns:key argument '{raw}'.")
            };
        }

        /// <summary>
        /// Parses a "vault:ns" pair with defaults applied.
        /// </summary>
        internal static (string Vault, string Ns) ParseVaultNs(
            string raw,
            string defaultVault = "default",
            string defaultNs = "default")
        {
            var parts = raw.Split(':', 2);
            return parts.Length switch
            {
                2 => (parts[0], parts[1]),
                1 => (defaultVault, parts[0]),
                _ => throw new ArgumentException($"Invalid vault:ns argument '{raw}'.")
            };
        }

        // ------------------------------------------------------------------ //
        //  Unlock context
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Builds an UnlockContext from CLI options.
        /// Prompts for passphrase interactively if --passphrase is specified without a value.
        /// </summary>
        internal static UnlockContext BuildUnlock(
            bool useTpm,
            bool usePassphrase,
            string? passphrase,
            string? privateKeyPath)
        {
            if (useTpm)
                return UnlockContext.TpmBound;

            if (usePassphrase)
            {
                var pp = passphrase
                    ?? AnsiConsole.Prompt(new TextPrompt<string>("Passphrase:").Secret());
                return UnlockContext.FromPassphrase(Encoding.UTF8.GetBytes(pp));
            }

            if (privateKeyPath is not null)
            {
                var keyBytes = File.ReadAllBytes(privateKeyPath);
                return UnlockContext.FromPrivateKey(keyBytes);
            }

            // Default: TPM-bound (no passphrase/key needed).
            return UnlockContext.TpmBound;
        }

        // ------------------------------------------------------------------ //
        //  Error display
        // ------------------------------------------------------------------ //

        internal static int HandleError(Exception ex)
        {
            AnsiConsole.MarkupLine($"[red]Error:[/] {ex.Message}");
            return 1;
        }
    }
}
