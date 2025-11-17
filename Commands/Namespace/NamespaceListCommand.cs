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
    public class NamespaceListCommand : Command<NamespaceListCommandSettings>
    {
        public override int Execute(CommandContext context, NamespaceListCommandSettings settings, CancellationToken cancellationToken)
        {
            var ns = settings.Namespace ?? "default";
            var workingDirectory = Environment.CurrentDirectory;
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

            var vaultSecretsResult = vaultService.ExportPlaintext(vault, ns);
            if (vaultSecretsResult.IsFailure)
            {
                AnsiConsole.MarkupLine(vaultSecretsResult.ErrorMessage!);
                return 1;
            }

            var vaultSecrets = vaultSecretsResult.Data!;
            if (settings.ListValues)
            {
                AnsiConsole.MarkupLine("[green]-[/] Retrieved all configurations:");
                foreach (var kvp in vaultSecrets)
                {
                    AnsiConsole.MarkupLine($"[blue]{ns}::{kvp.Key}[/] = [blue]{kvp.Value}[/]");
                }

                return 0;
            }

            AnsiConsole.MarkupLine("[green]-[/] Retrieved all keys:");
            foreach (var kvp in vaultSecrets)
            {
                AnsiConsole.MarkupLine($"[blue]{ns}::{kvp.Key}[/]");
            }

            return 0;
        }
    }
}
