using Spectre.Console;
using Spectre.Console.Cli;
using Synccl.Cli.Composition;
using Synccl.Cli.Settings.Namespace;
using Synccl.Core.Diff;
using Synccl.Core.Env;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Commands.Namespace
{
    public class NamespacePullCommand : Command<NamespacePullCommandSettings>
    {
        public override int Execute(CommandContext context, NamespacePullCommandSettings settings, CancellationToken cancellationToken)
        {
            var targetNs = settings.Namespace ?? "default";
            var sourceNs = settings.SourceNamespace ?? "default";
            var workingDirectory = Environment.CurrentDirectory;
            var vaultService = ServiceFactory.CreateVaultService(workingDirectory);

            var vaultResult = vaultService.LoadVault();
            if (vaultResult.IsFailure)
            {
                AnsiConsole.MarkupLine(vaultResult.ErrorMessage!);
                return 1;
            }

            var vault = vaultResult.Data!;
            var nameSpace = vault.Namespaces.FirstOrDefault(x => x.Name == targetNs);
            if (nameSpace == null)
            {
                AnsiConsole.MarkupLine($"[red]![/] Namespace [blue]{targetNs}[/] not found.");
                return 1;
            }

            nameSpace = vault.Namespaces.FirstOrDefault(x => x.Name == sourceNs);
            if (nameSpace == null)
            {
                AnsiConsole.MarkupLine($"[red]![/] Namespace [blue]{targetNs}[/] not found.");
                return 1;
            }

            var targetSecretsResult = vaultService.ExportPlaintext(vault, targetNs);
            if (targetSecretsResult.IsFailure)
            {
                AnsiConsole.MarkupLine(targetSecretsResult.ErrorMessage!);
                return 1;
            }

            var sourceSecretsResult = vaultService.ExportPlaintext(vault, sourceNs);
            if (sourceSecretsResult.IsFailure)
            {
                AnsiConsole.MarkupLine(sourceSecretsResult.ErrorMessage!);
                return 1;
            }

            var targetSecrets = targetSecretsResult.Data!;
            var sourceSecrets = sourceSecretsResult.Data!;
            var diff = SecretDiffEngine.Compare(sourceSecrets, targetSecrets);
            var mode = settings.Hard ? SecretDiffEngine.ChangeApplicationMode.AddOrUpdateOrDelete :
                settings.Merge ? SecretDiffEngine.ChangeApplicationMode.Add :
                SecretDiffEngine.ChangeApplicationMode.AddOrUpdate;

            var result = SecretDiffEngine.ApplyDiff(diff, sourceSecrets, targetSecrets, mode).ToDictionary();

            var importResult = vaultService.ImportPlaintext(vault, result, targetNs);
            if (importResult.IsFailure)
            {
                AnsiConsole.MarkupLine(importResult.ErrorMessage!);
                return 1;
            }

            var saveResult = vaultService.Save(vault);
            if (saveResult.IsFailure)
            {
                AnsiConsole.MarkupLine(saveResult.ErrorMessage!);
                return 1;
            }

            AnsiConsole.MarkupLine($"[green]+[/] Pulled secrets from namespace [blue]{sourceNs}[/] to [blue]{targetNs}[/].");
            return 0;
        }
    }
}
