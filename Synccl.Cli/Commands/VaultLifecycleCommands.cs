using Spectre.Console;
using Spectre.Console.Cli;
using System.ComponentModel;

namespace Synccl.Cli.Commands
{
    internal sealed class InitCommand : Command<InitCommand.Settings>
    {
        public sealed class Settings : CommandSettings
        {
            [CommandArgument(0, "[vault]")]
            [Description("Vault name (default: 'default')")]
            public string VaultName { get; init; } = "default";

            [CommandOption("-n|--namespace")]
            [Description("Default namespace name (default: 'default')")]
            public string DefaultNamespace { get; init; } = "default";
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                var svc = ServiceFactory.Create();
                var info = svc.InitVault(settings.VaultName, settings.DefaultNamespace);
                AnsiConsole.MarkupLine($"[green]Vault '[bold]{info.Name}[/]' created.[/]");
                AnsiConsole.MarkupLine($"  Store: {info.FilePath}");
                AnsiConsole.MarkupLine($"  Default namespace: {info.DefaultNamespaceName}");
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    internal sealed class DestroyCommand : Command<DestroyCommand.Settings>
    {
        public sealed class Settings : CommandSettings
        {
            [CommandArgument(0, "[vault]")]
            [Description("Vault name (default: 'default')")]
            public string VaultName { get; init; } = "default";

            [CommandOption("-f|--force")]
            [Description("Skip confirmation prompt")]
            public bool Force { get; init; }
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                if (!settings.Force)
                {
                    if (!AnsiConsole.Confirm($"[red]Destroy vault '{settings.VaultName}'? All data will be lost.[/]"))
                        return 0;
                }
                var svc = ServiceFactory.Create();
                svc.DestroyVault(settings.VaultName);
                AnsiConsole.MarkupLine($"[green]Vault '[bold]{settings.VaultName}[/]' destroyed.[/]");
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    internal sealed class VaultInfoCommand : Command<VaultInfoCommand.Settings>
    {
        public sealed class Settings : CommandSettings
        {
            [CommandArgument(0, "[vault]")]
            [Description("Vault name (default: 'default')")]
            public string VaultName { get; init; } = "default";
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                var svc = ServiceFactory.Create();
                var info = svc.GetVaultInfo(settings.VaultName);

                var table = new Table().AddColumns("Field", "Value");
                table.AddRow("Name", info.Name);
                table.AddRow("ID", info.Id.ToString());
                table.AddRow("Version", info.Version.ToString());
                table.AddRow("Access Mode", info.AccessMode);
                table.AddRow("Default Namespace", info.DefaultNamespaceName);
                table.AddRow("Namespaces", string.Join(", ", info.NamespaceNames));
                table.AddRow("File", info.FilePath);
                AnsiConsole.Write(table);
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    internal sealed class ListVaultsCommand : Command<ListVaultsCommand.Settings>
    {
        public sealed class Settings : CommandSettings { }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                var svc = ServiceFactory.Create();
                var vaults = svc.ListVaults();
                if (vaults.Count == 0) { AnsiConsole.MarkupLine("[grey]No vaults found.[/]"); return 0; }
                var table = new Table().AddColumns("Name", "Namespaces", "Version", "Access Mode");
                foreach (var v in vaults)
                    table.AddRow(v.Name, string.Join(", ", v.NamespaceNames), v.Version.ToString(), v.AccessMode);
                AnsiConsole.Write(table);
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    internal sealed class CreateVaultCommand : Command<CreateVaultCommand.Settings>
    {
        public sealed class Settings : CommandSettings
        {
            [CommandArgument(0, "<vault>")]
            [Description("Name for the new vault")]
            public string VaultName { get; init; } = string.Empty;

            [CommandOption("-n|--namespace")]
            [Description("Default namespace name (default: 'default')")]
            public string DefaultNamespace { get; init; } = "default";
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                var svc = ServiceFactory.Create();
                var info = svc.CreateVault(settings.VaultName, settings.DefaultNamespace);
                AnsiConsole.MarkupLine($"[green]Vault '[bold]{info.Name}[/]' created.[/]");
                AnsiConsole.MarkupLine($"  Store: {info.FilePath}");
                AnsiConsole.MarkupLine($"  Default namespace: {info.DefaultNamespaceName}");
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    internal sealed class RenameVaultCommand : Command<RenameVaultCommand.Settings>
    {
        public sealed class Settings : CommandSettings
        {
            [CommandArgument(0, "<vault>")]
            public string VaultName { get; init; } = string.Empty;

            [CommandArgument(1, "<newName>")]
            public string NewName { get; init; } = string.Empty;
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                var svc = ServiceFactory.Create();
                svc.RenameVault(settings.VaultName, settings.NewName);
                AnsiConsole.MarkupLine($"[green]Vault renamed to '[bold]{settings.NewName}[/]'.[/]");
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    internal sealed class MountCommand : Command<MountCommand.Settings>
    {
        public sealed class Settings : CommandSettings
        {
            [CommandArgument(0, "<file>")]
            [Description("Path to the .vault.json.unmounted file to import")]
            public string InputFilePath { get; init; } = string.Empty;

            [CommandOption("--passphrase")]
            [Description("Unlock the portable vault file with a passphrase (prompts if omitted)")]
            public bool UsePassphrase { get; init; }

            [CommandOption("--passphrase-value")]
            [Description("Passphrase value (insecure; prefer interactive prompt)")]
            public string? PassphraseValue { get; init; }

            [CommandOption("--private-key")]
            [Description("Path to X25519 private key file used to unlock the portable vault file")]
            public string? PrivateKeyPath { get; init; }
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(settings.InputFilePath))
                {
                    AnsiConsole.MarkupLine("[red]Error:[/] Provide the path to the [bold].vault.json.unmounted[/] file.");
                    return 1;
                }

                if (!settings.UsePassphrase && settings.PrivateKeyPath is null)
                {
                    AnsiConsole.MarkupLine("[red]Error:[/] Specify [bold]--passphrase[/] or [bold]--private-key <path>[/] to unlock the vault.");
                    return 1;
                }

                var transportUnlock = CliHelpers.BuildUnlock(
                    useTpm: false,
                    usePassphrase: settings.UsePassphrase,
                    passphrase: settings.PassphraseValue,
                    privateKeyPath: settings.PrivateKeyPath);

                ServiceFactory.Create().Mount(settings.InputFilePath, transportUnlock);
                AnsiConsole.MarkupLine($"[green]Vault mounted from '[bold]{settings.InputFilePath}[/]' — now bound to this device's TPM.[/]");
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    internal sealed class UnmountCommand : Command<UnmountCommand.Settings>
    {
        public sealed class Settings : CommandSettings
        {
            [CommandArgument(0, "[vault]")]
            [Description("Vault name (default: 'default')")]
            public string VaultName { get; init; } = "default";

            [CommandOption("--output")]
            [Description("Directory to write the .vault.json.unmounted file (defaults to current directory)")]
            public string? OutputPath { get; init; }

            [CommandOption("--passphrase")]
            [Description("Protect the portable vault file with a passphrase (prompts if omitted)")]
            public bool UsePassphrase { get; init; }

            [CommandOption("--passphrase-value")]
            [Description("Passphrase value (insecure; prefer interactive prompt)")]
            public string? PassphraseValue { get; init; }

            [CommandOption("--private-key")]
            [Description("Path to X25519 private key used to protect the portable vault file")]
            public string? PrivateKeyPath { get; init; }
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                if (!settings.UsePassphrase && settings.PrivateKeyPath is null)
                {
                    AnsiConsole.MarkupLine("[red]Error:[/] Specify [bold]--passphrase[/] or [bold]--private-key <path>[/] to protect the portable vault file.");
                    return 1;
                }

                var transportProtection = CliHelpers.BuildUnlock(
                    useTpm: false,
                    usePassphrase: settings.UsePassphrase,
                    passphrase: settings.PassphraseValue,
                    privateKeyPath: settings.PrivateKeyPath);

                var filePath = ServiceFactory.Create().Unmount(settings.VaultName, transportProtection, settings.OutputPath);
                AnsiConsole.MarkupLine($"[green]Vault '[bold]{settings.VaultName}[/]' unmounted.[/] Portable file: [bold]{filePath}[/]");
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }
}
