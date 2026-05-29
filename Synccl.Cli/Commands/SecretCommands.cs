using Spectre.Console;
using Spectre.Console.Cli;
using System.ComponentModel;

namespace Synccl.Cli.Commands
{
    // Shared settings base for commands that need vault unlock.
    internal abstract class UnlockSettings : CommandSettings
    {
        [CommandOption("--passphrase")]
        [Description("Unlock with a passphrase (will prompt if value omitted)")]
        public bool UsePassphrase { get; init; }

        [CommandOption("--passphrase-value")]
        [Description("Passphrase value (avoid; prefer interactive prompt)")]
        public string? PassphraseValue { get; init; }

        [CommandOption("--private-key")]
        [Description("Path to X25519 private key file")]
        public string? PrivateKeyPath { get; init; }

        internal Synccl.Core.Model.UnlockContext BuildUnlock()
            => CliHelpers.BuildUnlock(
                useTpm: !UsePassphrase && PrivateKeyPath is null,
                usePassphrase: UsePassphrase,
                passphrase: PassphraseValue,
                privateKeyPath: PrivateKeyPath);
    }

    // ---------------------------------------------------------------------- //
    //  set
    // ---------------------------------------------------------------------- //

    internal sealed class SetSecretCommand : Command<SetSecretCommand.Settings>
    {
        public sealed class Settings : UnlockSettings
        {
            [CommandArgument(0, "<vault:ns:key>")]
            [Description("Target in vault:namespace:key format")]
            public string Target { get; init; } = string.Empty;

            [CommandArgument(1, "<value>")]
            public string Value { get; init; } = string.Empty;
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                var (vault, ns, key) = CliHelpers.ParseVaultNsKey(settings.Target);
                ServiceFactory.Create().SetSecret(vault, ns, key, settings.Value, settings.BuildUnlock());
                AnsiConsole.MarkupLine($"[green]Set [bold]{key}[/] in {vault}:{ns}.[/]");
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    // ---------------------------------------------------------------------- //
    //  get
    // ---------------------------------------------------------------------- //

    internal sealed class GetSecretCommand : Command<GetSecretCommand.Settings>
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
                var value = ServiceFactory.Create().GetSecret(vault, ns, key, settings.BuildUnlock());
                AnsiConsole.WriteLine(value);
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    // ---------------------------------------------------------------------- //
    //  unset
    // ---------------------------------------------------------------------- //

    internal sealed class UnsetSecretCommand : Command<UnsetSecretCommand.Settings>
    {
        public sealed class Settings : CommandSettings
        {
            [CommandArgument(0, "<vault:ns:key>")]
            public string Target { get; init; } = string.Empty;
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                var (vault, ns, key) = CliHelpers.ParseVaultNsKey(settings.Target);
                ServiceFactory.Create().UnsetSecret(vault, ns, key);
                AnsiConsole.MarkupLine($"[green]Unset [bold]{key}[/] from {vault}:{ns}.[/]");
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    // ---------------------------------------------------------------------- //
    //  list
    // ---------------------------------------------------------------------- //

    internal sealed class ListSecretsCommand : Command<ListSecretsCommand.Settings>
    {
        public sealed class Settings : UnlockSettings
        {
            [CommandArgument(0, "[vault:ns]")]
            public string Target { get; init; } = "default:default";

            [CommandOption("-v|--values")]
            [Description("Also show values (requires unlock)")]
            public bool ShowValues { get; init; }
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                var (vault, ns) = CliHelpers.ParseVaultNs(settings.Target);
                var secrets = ServiceFactory.Create()
                    .ListSecrets(vault, ns, settings.ShowValues, settings.BuildUnlock());

                if (secrets.Count == 0) { AnsiConsole.MarkupLine("[grey]No secrets found.[/]"); return 0; }

                if (settings.ShowValues)
                {
                    var table = new Table().AddColumns("Key", "Value");
                    foreach (var (k, v) in secrets) table.AddRow(k, v);
                    AnsiConsole.Write(table);
                }
                else
                {
                    foreach (var k in secrets.Keys) AnsiConsole.WriteLine(k);
                }
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }
}
