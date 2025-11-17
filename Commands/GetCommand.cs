using Spectre.Console;
using Spectre.Console.Cli;
using Synccl.Cli.Composition;
using Synccl.Cli.Helpers;
using Synccl.Cli.Settings;
using Synccl.Core.Vault;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Commands
{
    public class GetCommand : Command<GetCommandSettings>
    {
        public override int Execute(CommandContext context, GetCommandSettings settings, CancellationToken cancellationToken)
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

            var getSecretResult = vaultService.GetSecret(vault, ns, key);
            if (getSecretResult.IsFailure)
            {
                AnsiConsole.MarkupLine(getSecretResult.ErrorMessage!);
                return 1;
            }

            AnsiConsole.MarkupLine($"[green]-[/] Retrieved configuration: [blue]{ns}::{key}[/] = [blue]{getSecretResult.Data!}[/]");
            return 0;
        }
    }
}
