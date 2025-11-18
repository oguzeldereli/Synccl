using Spectre.Console;
using Spectre.Console.Cli;
using Synccl.Cli.Composition;
using Synccl.Cli.Settings.Env;
using Synccl.Core.Diff;
using Synccl.Core.Env;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Commands.Env
{
    public class EnvPushCommand : Command<EnvPushCommandSettings>
    {
        public override int Execute(CommandContext context, EnvPushCommandSettings settings, CancellationToken cancellationToken)
        {
            var ns = settings.Namespace ?? "default";
            var envPath = settings.Path;
            if (!File.Exists(envPath))
            {
                AnsiConsole.MarkupLine($"[red]![/] .env file not found at path: {envPath}");
                return 1;
            }

            var workingDirectory = Environment.CurrentDirectory;
            var vaultService = ServiceFactory.CreateVaultService(workingDirectory);

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
            var envFile = EnvFile.Parse(envPath);
            var envDict = EnvFile.ToDictionary(envFile);
            var diff = SecretDiffEngine.Compare(envDict, vaultSecrets);
            var mode = settings.Prune ? SecretDiffEngine.ChangeApplicationMode.AddOrUpdateOrDelete :
                settings.Strict ? SecretDiffEngine.ChangeApplicationMode.Add :
                SecretDiffEngine.ChangeApplicationMode.AddOrUpdate;

            var result = SecretDiffEngine.ApplyDiff(diff, envDict, vaultSecrets, mode).ToDictionary();

            vaultService.ImportPlaintext(vault, result, ns);
            vaultService.Save(vault);

            AnsiConsole.MarkupLine($"[green]-[/] Pushed environment variables from [blue]{envPath}[/] to vault.");
            if (settings.Prune)
            {
                AnsiConsole.MarkupLine($"[yellow]![/] Existing vault entries were overwritten.");
            }
            return 0;
        }
    }
}
