
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
    public class NamespacesCreateCommand : Command<NamespacesCreateCommandSettings>
    {
        public override int Execute(CommandContext context, NamespacesCreateCommandSettings settings, CancellationToken cancellationToken)
        {
            var workingDirectory = Environment.CurrentDirectory;
            var vaultService = ServiceFactory.CreateVaultService(workingDirectory);

            var vaultResult = vaultService.LoadVault();
            if (vaultResult.IsFailure)
            {
                AnsiConsole.MarkupLine(vaultResult.ErrorMessage!);
                return 1;
            }

            var vault = vaultResult.Data!;
            if (vault.Namespaces.Any(n => n.Name.Equals(settings.Name, StringComparison.OrdinalIgnoreCase)))
            {
                AnsiConsole.MarkupLine($"[red]Error:[/] Namespace '{settings.Name}' already exists.");
                return 1;
            }
            
            var createResult = vaultService.CreateNamespace(vault, settings.Name);
            if (createResult.IsFailure)
            {
                AnsiConsole.MarkupLine(createResult.ErrorMessage!);
                return 1;
            }

            var saveResult = vaultService.Save(vault);
            if (saveResult.IsFailure)
            {
                AnsiConsole.MarkupLine(saveResult.ErrorMessage!);
                return 1;
            }

            AnsiConsole.MarkupLine($"[green]Success:[/] Namespace '{settings.Name}' added.");
            return 0;
        }
    }
}
