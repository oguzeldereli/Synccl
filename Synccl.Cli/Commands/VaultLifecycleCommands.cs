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
}
