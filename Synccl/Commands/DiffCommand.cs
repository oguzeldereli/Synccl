
using Spectre.Console;
using Spectre.Console.Cli;
using Synccl.Cli.Composition;
using Synccl.Cli.Settings;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Commands
{
    public class DiffCommand : Command<DiffCommandSettings>
    {
        public override int Execute(CommandContext context, DiffCommandSettings settings, CancellationToken cancellationToken)
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

            var result = remote.DiffAsync(
                workingDir,
                localNs,
                remoteNs
            ).GetAwaiter().GetResult();

            if (result.IsFailure)
            {
                AnsiConsole.MarkupLine(result.ErrorMessage!);
                return 1;
            }

            var resultData = result.Data!;
            var table = resultData.ToTable($"{localNs} diff {settings.RemoteName}:{remoteNs}", localNs, $"{settings.RemoteName}:{remoteNs}");
            AnsiConsole.Write(table);
            return 0;
        }
    }
}
