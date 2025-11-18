using Spectre.Console;
using Spectre.Console.Cli;
using Synccl.Cli.Composition;
using Synccl.Cli.Helpers;
using Synccl.Cli.Settings.Namespace;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Commands.Namespace
{
    public class NamespaceUnsetCommand : Command<NamespaceUnsetCommandSettings>
    {
        public override int Execute(CommandContext context, NamespaceUnsetCommandSettings settings, CancellationToken cancellationToken)
        {
            var nonNullNs = settings.Namespace ?? "default";
            var (ns, key) = KeyNamespaceExtractor.Extract(settings.Key, nonNullNs);
            var workingDirectory = Environment.CurrentDirectory;
            var vaultService = ServiceFactory.CreateVaultService(workingDirectory);
            if (vaultService == null)
            {
                AnsiConsole.MarkupLine("[red]Error:[/] Unable to create vault service.");
                return 1;
            }

            var vaultResult = vaultService.LoadVault();
            if (vaultResult.IsFailure)
            {
                AnsiConsole.MarkupLine(vaultResult.ErrorMessage!);
                return 1;
            }

            var vault = vaultResult.Data!;
            var nameSpace = vault.Namespaces.FirstOrDefault(x => x.Name == ns);
            if (nameSpace == null)
            {
                AnsiConsole.MarkupLine($"[red]![/] Namespace [blue]{ns}[/] not found.");
                return 1;
            }

            var result = vaultService.UnsetSecret(vault, ns, key);
            if (result.IsFailure)
            {
                AnsiConsole.MarkupLine(result.ErrorMessage!);
                return 1;
            }

            var saveResult = vaultService.Save(vault);
            if (saveResult.IsFailure)
            {
                AnsiConsole.MarkupLine(saveResult.ErrorMessage!);
                return 1;
            }

            AnsiConsole.MarkupLine($"[green]+[/] Successfully removed the key [blue]{ns}::{key}[/] from the vault.");
            return 0;
        }
    }
}
