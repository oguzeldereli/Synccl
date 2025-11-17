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
    public class SetCommand : Command<SetCommandSettings>
    {
        public override int Execute(CommandContext context, SetCommandSettings settings, CancellationToken cancellationToken)
        {
            var value = settings.Value;
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
            var result = vaultService.SetSecret(vault, ns, key, value);
            if (result.IsFailure)
            {
                AnsiConsole.MarkupLine(vaultResult.ErrorMessage!);
                return 1;
            }

            vaultService.Save(vault);
            AnsiConsole.MarkupLine($"[green]-[/] Setting configuration: [blue]{ns}::{Markup.Escape(key)}[/] = [blue]{Markup.Escape(value)}[/]");
            return 0;
        }
    }
}
