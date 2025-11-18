using Spectre.Console;
using Spectre.Console.Cli;
using Synccl.Cli.Composition;
using Synccl.Cli.Settings;

namespace Synccl.Cli.Commands
{
    public class ListCommand : Command<ListCommandSettings>
    {
        public override int Execute(CommandContext context, ListCommandSettings settings, CancellationToken cancellationToken)
        {
            var ns = settings.Namespace ?? "default";
            var workingDirectory = Environment.CurrentDirectory;
            var vaultService = ServiceFactory.CreateVaultService(workingDirectory);

            var vaultResult = vaultService.TryLoadVault();
            if (vaultResult.IsFailure)
            {
                AnsiConsole.MarkupLine(vaultResult.ErrorMessage!);
                return 1;
            }

            var vault = vaultResult.Data!;
            if (vault.Namespaces.Count == 0)
            {
                AnsiConsole.MarkupLine("[red]![/] No namespaces found in vault.");
                return 1;
            }

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
