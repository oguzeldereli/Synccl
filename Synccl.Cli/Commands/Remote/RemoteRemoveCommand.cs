using Spectre.Console;
using Spectre.Console.Cli;
using Synccl.Cli.Config;
using Synccl.Cli.Settings.Remote;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Commands.Remote
{
    public class RemoteRemoveCommand : Command<RemoteRemoveCommandSettings>
    {
        public override int Execute(CommandContext context, RemoteRemoveCommandSettings settings, CancellationToken cancellationToken)
        {
            var name = string.IsNullOrWhiteSpace(settings.Name) ? "origin" : settings.Name;
            var path = Directory.GetCurrentDirectory();
            var config = ConfigLoader.TryLoadConfig(path);

            if (!config.Remotes.Any(x => x?.Name == name))
            {
                AnsiConsole.MarkupLine($"[red]![/] No remote with name [blue]{name}[/] found.");
                return 1;
            }

            config.Remotes.RemoveAll(x => x?.Name == name);
            ConfigLoader.SaveConfig(path, config);
            AnsiConsole.MarkupLine($"[green]+[/] Remote [blue]{name}[/] removed successfully.");
            return 0;
        }
    }
}
