using Spectre.Console;
using Spectre.Console.Cli;
using System.ComponentModel;

namespace Synccl.Cli.Commands
{
    // ---------------------------------------------------------------------- //
    //  rotate vault
    // ---------------------------------------------------------------------- //

    internal sealed class RotateVaultKeyCommand : Command<RotateVaultKeyCommand.Settings>
    {
        public sealed class Settings : UnlockSettings
        {
            [CommandArgument(0, "[vault]")]
            public string VaultName { get; init; } = "default";

            [CommandOption("-a|--all")]
            [Description("Also rotate all namespace and item keys")]
            public bool RotateAll { get; init; }
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                ServiceFactory.Create().RotateVaultKey(settings.VaultName, settings.BuildUnlock(), settings.RotateAll);
                AnsiConsole.MarkupLine($"[green]Vault key rotated for '[bold]{settings.VaultName}[/]'.[/]");
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    // ---------------------------------------------------------------------- //
    //  rotate namespace
    // ---------------------------------------------------------------------- //

    internal sealed class RotateNamespaceKeyCommand : Command<RotateNamespaceKeyCommand.Settings>
    {
        public sealed class Settings : UnlockSettings
        {
            [CommandArgument(0, "<vault:ns>")]
            public string Target { get; init; } = string.Empty;

            [CommandOption("-a|--all")]
            [Description("Also rotate all item keys in the namespace")]
            public bool RotateAll { get; init; }
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                var (vault, ns) = CliHelpers.ParseVaultNs(settings.Target);
                ServiceFactory.Create().RotateNamespaceKey(vault, ns, settings.BuildUnlock(), settings.RotateAll);
                AnsiConsole.MarkupLine($"[green]Namespace key rotated for {vault}:{ns}.[/]");
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    // ---------------------------------------------------------------------- //
    //  rotate key (item)
    // ---------------------------------------------------------------------- //

    internal sealed class RotateItemKeyCommand : Command<RotateItemKeyCommand.Settings>
    {
        public sealed class Settings : UnlockSettings
        {
            [CommandArgument(0, "<vault:ns:key>")]
            public string Target { get; init; } = string.Empty;
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                var (vault, ns, key) = CliHelpers.ParseVaultNsKey(settings.Target);
                ServiceFactory.Create().RotateItemKey(vault, ns, key, settings.BuildUnlock());
                AnsiConsole.MarkupLine($"[green]Item key rotated for {vault}:{ns}:{key}.[/]");
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    // ---------------------------------------------------------------------- //
    //  protect / unprotect
    // ---------------------------------------------------------------------- //

    internal sealed class ProtectCommand : Command<ProtectCommand.Settings>
    {
        public sealed class Settings : UnlockSettings
        {
            [CommandArgument(0, "[vault]")]
            public string VaultName { get; init; } = "default";

            [CommandOption("--new-passphrase")]
            [Description("Protect with a new passphrase")]
            public bool NewPassphrase { get; init; }

            [CommandOption("--new-passphrase-value")]
            public string? NewPassphraseValue { get; init; }

            [CommandOption("--new-private-key")]
            [Description("Protect with a new X25519 private key file")]
            public string? NewPrivateKeyPath { get; init; }
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                if (!settings.NewPassphrase && settings.NewPrivateKeyPath is null)
                {
                    AnsiConsole.MarkupLine("[red]Error:[/] Specify [bold]--new-passphrase[/] or [bold]--new-private-key <path>[/].");
                    return 1;
                }

                var newProtection = CliHelpers.BuildUnlock(
                    useTpm: false,
                    usePassphrase: settings.NewPassphrase,
                    passphrase: settings.NewPassphraseValue,
                    privateKeyPath: settings.NewPrivateKeyPath);

                ServiceFactory.Create().Protect(settings.VaultName, settings.BuildUnlock(), newProtection);
                AnsiConsole.MarkupLine($"[green]Vault '[bold]{settings.VaultName}[/]' protected.[/]");
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    internal sealed class UnprotectCommand : Command<UnprotectCommand.Settings>
    {
        public sealed class Settings : UnlockSettings
        {
            [CommandArgument(0, "[vault]")]
            public string VaultName { get; init; } = "default";
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                ServiceFactory.Create().Unprotect(settings.VaultName, settings.BuildUnlock());
                AnsiConsole.MarkupLine($"[green]Vault '[bold]{settings.VaultName}[/]' unprotected (TPM-only).[/]");
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }
}
