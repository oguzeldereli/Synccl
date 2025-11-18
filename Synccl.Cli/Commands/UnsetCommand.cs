using Spectre.Console;
using Spectre.Console.Cli;
using Synccl.Cli.Composition;
using Synccl.Cli.Helpers;
using Synccl.Cli.Settings;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Commands
{
    public class UnsetCommand : Command<UnsetCommandSettings>
    {
        public override int Execute(CommandContext context, UnsetCommandSettings settings, CancellationToken cancellationToken)
        {
            var workingDirectory = Environment.CurrentDirectory;
            var vaultService = ServiceFactory.CreateVaultService(workingDirectory);
            var (ns, key) = KeyNamespaceExtractor.Extract(settings.Key, settings.Namespace);

            var vaultResult = vaultService.TryLoadVault();
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
                AnsiConsole.MarkupLine($"[yellow]![/] The key [blue]{ns}::{key}[/] does not exist in the vault.");
                return 1;
            }

            vaultService.Save(vault);
            AnsiConsole.MarkupLine($"[green]+[/] Successfully removed the key [blue]{ns}::{key}[/] from the vault.");
            return 0;
        }
    }
}
