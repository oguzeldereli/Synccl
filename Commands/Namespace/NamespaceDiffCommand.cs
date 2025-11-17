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
    public class NamespaceDiffCommand : Command<NamespaceDiffCommandSettings>
    {
        public override int Execute(CommandContext context, NamespaceDiffCommandSettings settings, CancellationToken cancellationToken)
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

            if (!diff.Changes.Any(c => c.Type != SecretChangeType.NoChange))
            {
                AnsiConsole.MarkupLine("[green]+[/] No differences found between the namespaces.");
                return 0;
            }

            var table = diff.ToTable($"{sourceNs} diff {targetNs}", sourceNs, targetNs);
            AnsiConsole.Write(table);
            AnsiConsole.MarkupLine($"[italic grey]Tip: run [bold]synccl namespace {targetNs} pull {sourceNs}[/] or [bold]synccl namespace {sourceNs} push {targetNs}[/][/]");

            return 0;
        }
    }
}
