using Spectre.Console;
using Spectre.Console.Cli;
using System.ComponentModel;

namespace Synccl.Cli.Commands
{
    // ---------------------------------------------------------------------- //
    //  namespace add / remove / list
    // ---------------------------------------------------------------------- //

    internal sealed class AddNamespaceCommand : Command<AddNamespaceCommand.Settings>
    {
        public sealed class Settings : UnlockSettings
        {
            [CommandArgument(0, "<vault>")]
            public string VaultName { get; init; } = string.Empty;

            [CommandArgument(1, "<namespace>")]
            public string NamespaceName { get; init; } = string.Empty;
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                ServiceFactory.Create().AddNamespace(settings.VaultName, settings.NamespaceName, settings.BuildUnlock());
                AnsiConsole.MarkupLine($"[green]Namespace '[bold]{settings.NamespaceName}[/]' added.[/]");
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    internal sealed class RemoveNamespaceCommand : Command<RemoveNamespaceCommand.Settings>
    {
        public sealed class Settings : CommandSettings
        {
            [CommandArgument(0, "<vault>")]
            public string VaultName { get; init; } = string.Empty;

            [CommandArgument(1, "<namespace>")]
            public string NamespaceName { get; init; } = string.Empty;

            [CommandOption("-f|--force")]
            public bool Force { get; init; }
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                if (!settings.Force &&
                    !AnsiConsole.Confirm($"Remove namespace '{settings.NamespaceName}' and all its secrets?"))
                    return 0;

                ServiceFactory.Create().RemoveNamespace(settings.VaultName, settings.NamespaceName);
                AnsiConsole.MarkupLine($"[green]Namespace '[bold]{settings.NamespaceName}[/]' removed.[/]");
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    internal sealed class ListNamespacesCommand : Command<ListNamespacesCommand.Settings>
    {
        public sealed class Settings : CommandSettings
        {
            [CommandArgument(0, "[vault]")]
            public string VaultName { get; init; } = "default";
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                var nss = ServiceFactory.Create().ListNamespaces(settings.VaultName);
                if (nss.Count == 0) { AnsiConsole.MarkupLine("[grey]No namespaces found.[/]"); return 0; }
                foreach (var ns in nss) AnsiConsole.WriteLine(ns);
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }
}
