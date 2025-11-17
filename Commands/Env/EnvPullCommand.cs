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
    public class EnvPullCommand : Command<EnvPullCommandSettings>
    {
        public override int Execute(CommandContext context, EnvPullCommandSettings settings, CancellationToken cancellationToken)
        {
            var ns = settings.Namespace ?? "default";
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

            var envPath = settings.Path;
            if (!File.Exists(envPath))
            {
                File.Create(envPath).Dispose();
            }

            var vaultSecrets = vaultSecretsResult.Data!;
            var envFile = EnvFile.Parse(envPath);
            var envDict = EnvFile.ToDictionary(envFile);
            var diff = SecretDiffEngine.Compare(vaultSecrets, envDict);
            var mode = settings.Hard ? SecretDiffEngine.ChangeApplicationMode.AddOrUpdateOrDelete :
                settings.Merge ? SecretDiffEngine.ChangeApplicationMode.Add :
                SecretDiffEngine.ChangeApplicationMode.AddOrUpdate;

            var result = SecretDiffEngine.ApplyDiff(diff, vaultSecrets, envDict, mode).ToDictionary();

            EnvFile.Write(envPath, EnvFile.ApplyValues(envFile, result));
            AnsiConsole.MarkupLine($"[green]-[/] Saved environment variables to [blue]{envPath}[/]");
            return 0;
        }
    }
}
