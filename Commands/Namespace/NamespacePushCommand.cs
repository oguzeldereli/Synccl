using Spectre.Console;
using Spectre.Console.Cli;
using Synccl.Cli.Composition;
using Synccl.Cli.Settings.Namespace;
using Synccl.Core.Diff;
using Synccl.Core.Vault;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Commands.Namespace
{
    public class NamespacePushCommand : Command<NamespacePushCommandSettings>
    {
        public override int Execute(CommandContext context, NamespacePushCommandSettings settings, CancellationToken cancellationToken)
        {
            var sourceNs = settings.Namespace ?? "default";
            var targetNs = settings.TargetNamespace ?? "default";
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
            if (targetSecretsResult == null)
            {
                AnsiConsole.MarkupLine("[red]![/] Failed to load vault secrets.");
                return 1;
            }

            var sourceSecretsResult = vaultService.ExportPlaintext(vault, sourceNs);
            if (sourceSecretsResult == null)
            {
                AnsiConsole.MarkupLine("[red]![/] Failed to load vault secrets.");
                return 1;
            }

            var sourceSecrets = sourceSecretsResult.Data!;
            var targetSecrets = targetSecretsResult.Data!;
            var diff = SecretDiffEngine.Compare(sourceSecrets, targetSecrets);
            var mode = settings.Prune ? SecretDiffEngine.ChangeApplicationMode.AddOrUpdateOrDelete :
                settings.Strict ? SecretDiffEngine.ChangeApplicationMode.Add :
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

            AnsiConsole.MarkupLine($"[green]![/] Successfully pushed secrets from [blue]{sourceNs}[/] to [blue]{targetNs}[/].");
            if (settings.Prune)
            {
                AnsiConsole.MarkupLine($"[yellow]![/] Prune option enabled: secrets not present in {sourceNs} have been deleted from {targetNs}.");
            }

            return 0;
        }
    }
}
