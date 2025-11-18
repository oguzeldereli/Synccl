using Spectre.Console;
using Spectre.Console.Cli;
using Synccl.Cli.Composition;
using Synccl.Cli.Settings.Namespaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Commands.Namespaces
{
    public class NamespaceDeleteCommand : Command<NamespacesDeleteCommandSettings>
    {
        public override int Execute(CommandContext context, NamespacesDeleteCommandSettings settings, CancellationToken cancellationToken)
        {
            if (!settings.Force)
            {
                var prompt = new ConfirmationPrompt($"[red]This will permenantly remove all keys in [blue]{settings.Namespace}[/]. Continue?[/]");
                prompt.DefaultValue = false;
                var confirm = AnsiConsole.Prompt(prompt);

                if (!confirm)
                {
                    AnsiConsole.MarkupLine("[yellow]![/] Operation cancelled.");
                    return 0;
                }
            }

            var workingDir = Environment.CurrentDirectory;
            var vaultService = ServiceFactory.CreateVaultService(workingDir);
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
            var ns = vault.Namespaces.FirstOrDefault(x => x.Name == settings.Namespace);
            if (ns == null)
            {
                AnsiConsole.MarkupLine($"[red]![/] Namespace [blue]{settings.Namespace}[/] not found.");
                return 1;
            }

            var removeResult = vaultService.DeleteNamespace(vault, ns.Name);
            if (removeResult.IsFailure)
            {
                AnsiConsole.MarkupLine(removeResult.ErrorMessage!);
                return 1;
            }

            var saveResult = vaultService.Save(vault);
            if (saveResult.IsFailure)
            {
                AnsiConsole.MarkupLine(saveResult.ErrorMessage!);
                return 1;
            }

            AnsiConsole.MarkupLine($"[green]-[/] Deleted namespace: [blue]{ns}[/]");
            return 0;
        }
    }
}
