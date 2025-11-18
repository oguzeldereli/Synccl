using Spectre.Console;
using Spectre.Console.Cli;
using Synccl.Cli.Composition;
using Synccl.Cli.Settings;
using Synccl.Core.Diff;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Commands
{
    public class PullCommand : Command<PullCommandSettings>
    {
        public override int Execute(CommandContext context, PullCommandSettings settings, CancellationToken cancellationToken)
        {
            var workingDir = Environment.CurrentDirectory;
            AnsiConsole.MarkupLine($"Connecting to remote '[green]{settings.RemoteName}[/]'...");
            var remote = ServiceFactory.CreateRemote(workingDir, settings.RemoteName);
            if (remote == null)
            {
                AnsiConsole.MarkupLine($"[red]![/] Remote '{settings.RemoteName}' not found. Add remote with [blue]synccl remote add[/]");
                return 1;
            }
            var localNs = settings.Namespace ?? "default";
            var remoteNs = settings.Namespace ?? "default";

            var mode = settings.Hard ? SecretDiffEngine.ChangeApplicationMode.AddOrUpdateOrDelete :
                settings.Merge ? SecretDiffEngine.ChangeApplicationMode.Add :
                SecretDiffEngine.ChangeApplicationMode.AddOrUpdate;

            var result = remote.PullAsync(
                workingDir,
                localNs,
                remoteNs,
                mode
            ).GetAwaiter().GetResult();

            if (result.IsFailure)
            {
                AnsiConsole.MarkupLine(result.ErrorMessage!);
                return 1;
            }

            AnsiConsole.MarkupLine($"[green]-[/] Pull from remote '[green]{settings.RemoteName}[/]' completed successfully.");
            return 0;
        }
    }
}
