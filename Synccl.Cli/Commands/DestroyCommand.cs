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
    public class DestroyCommand : Command<DestroySettings>
    {
        public override int Execute(CommandContext context, DestroySettings settings, CancellationToken cancellationToken)
        {
            var path = settings.Path;

            if (!settings.Force)
            {
                var prompt = new ConfirmationPrompt("[red]This will permanently delete your local Synccl vault and remove the keychain entry. Continue?[/]");
                prompt.DefaultValue = false;
                var confirm = AnsiConsole.Prompt(prompt);

                if (!confirm)
                {
                    AnsiConsole.MarkupLine("[yellow]Aborted.[/]");
                    return 0;
                }
            }

            var signer = ServiceFactory.GetSecureSigner(path);
            var wrapper = ServiceFactory.GetSecureKeyWrapper(path);

            wrapper.DeleteStorageParent();
            signer.DeleteSigningKey();
            signer.DeleteStorageParent();

            var dirPath = Path.Combine(path, ".synccl");
            if (Directory.Exists(dirPath))
            {
                Directory.Delete(dirPath, true);
                AnsiConsole.MarkupLine("[green]-[/] Removed .synccl directory");
            }
            else
            {
                AnsiConsole.MarkupLine("[yellow]![/] No .synccl directory found");
            }

            var cfgPath = Path.Combine(path, "synccl.yaml");
            if (settings.DeleteConfig && File.Exists(cfgPath))
            {
                File.Delete(cfgPath);
                AnsiConsole.MarkupLine("[green]-[/] Deleted synccl.yaml");
            }
            else if (settings.DeleteConfig)
            {
                AnsiConsole.MarkupLine("[yellow]![/] No synccl.yaml found");
            }
            else
            {
                AnsiConsole.MarkupLine("[yellow]![/] synccl.yaml not deleted (use --delete-config to remove)");
            }

            AnsiConsole.MarkupLine("[green]- Completed destruction of Synccl setup[/]");
            return 0;
        }
    }
}
