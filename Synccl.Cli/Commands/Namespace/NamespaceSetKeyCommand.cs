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
    public class NamespaceSetCommand : Command<NamespaceSetCommandSettings>
    {
        public override int Execute(CommandContext context, NamespaceSetCommandSettings settings, CancellationToken cancellationToken)
        {
            var nonNullNs = settings.Namespace ?? "default";
            var workingDirectory = Environment.CurrentDirectory;
            var (ns, key) = KeyNamespaceExtractor.Extract(settings.Key, nonNullNs);
            var vaultService = ServiceFactory.CreateVaultService(workingDirectory);
            if (vaultService == null)
            {
                AnsiConsole.MarkupLine("[red]![/] Failed to create vault service.");
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

            var result = vaultService.SetSecret(vault, ns, key, settings.Value);
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

            AnsiConsole.MarkupLine($"[green]-[/] Set configuration: [blue]{ns}::{key}[/] = [blue]{settings.Value}[/]");
            return 0;
        }
    }
}
