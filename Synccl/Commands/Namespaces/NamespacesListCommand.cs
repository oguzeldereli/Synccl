using Spectre.Console;
using Spectre.Console.Cli;
using Synccl.Cli.Composition;
using Synccl.Cli.Settings.Namespaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Commands.Namespaces
{
    public class NamespacesListCommand : Command<NamespacesListCommandSettings>
    {
        public override int Execute(CommandContext context, NamespacesListCommandSettings settings, CancellationToken cancellationToken)
        {
            var workingDirectory = Environment.CurrentDirectory;
            var vaultService = ServiceFactory.CreateVaultService(workingDirectory);
            if (vaultService == null)
            {
                AnsiConsole.MarkupLine("[red]![/] Failed to create vault service.");
                return 1;
            }

            var vaultResult = vaultService.TryLoadVault();
            if (vaultResult.IsFailure)
            {
                AnsiConsole.MarkupLine(vaultResult.ErrorMessage!);
                return 1;
            }

            var vault = vaultResult.Data!;
            var table = new Table();
            table.AddColumn("Namespace");
            table.AddColumn("Namespace ID");
            table.AddColumn("Secret Count");
            foreach (var ns in vault.Namespaces)
            {
                table.AddRow(ns.Name, ns.Id.ToString(), ns.Secrets.Count.ToString());
            }

            AnsiConsole.Write(table);
            return 0;
        }
    }
}
