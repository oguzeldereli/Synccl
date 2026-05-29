using Spectre.Console;
using Spectre.Console.Cli;
using System.ComponentModel;

namespace Synccl.Cli.Commands
{
    // ---------------------------------------------------------------------- //
    //  diff
    // ---------------------------------------------------------------------- //

    internal sealed class DiffCommand : Command<DiffCommand.Settings>
    {
        public sealed class Settings : UnlockSettings
        {
            [CommandArgument(0, "<source>")]
            [Description("Source in vault:ns format")]
            public string Source { get; init; } = string.Empty;

            [CommandArgument(1, "<destination>")]
            [Description("Destination in vault:ns format")]
            public string Destination { get; init; } = string.Empty;
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                var (sv, sn) = CliHelpers.ParseVaultNs(settings.Source);
                var (dv, dn) = CliHelpers.ParseVaultNs(settings.Destination);
                var result = ServiceFactory.Create().Diff(sv, sn, dv, dn, settings.BuildUnlock());

                if (!result.HasChanges) { AnsiConsole.MarkupLine("[grey]No differences.[/]"); return 0; }

                var table = new Table().AddColumns("Key", "Change", "Source", "Destination");
                foreach (var e in result.Entries)
                {
                    var kind = e.Kind switch
                    {
                        Core.Model.DiffEntryKind.Added => "[green]+[/]",
                        Core.Model.DiffEntryKind.Removed => "[red]-[/]",
                        Core.Model.DiffEntryKind.Modified => "[yellow]~[/]",
                        _ => " "
                    };
                    table.AddRow(e.Key, kind, e.SourceValue ?? "", e.DestinationValue ?? "");
                }
                AnsiConsole.Write(table);
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    // ---------------------------------------------------------------------- //
    //  push
    // ---------------------------------------------------------------------- //

    internal sealed class PushCommand : Command<PushCommand.Settings>
    {
        public sealed class Settings : UnlockSettings
        {
            [CommandArgument(0, "<source>")]
            public string Source { get; init; } = string.Empty;

            [CommandArgument(1, "<destination>")]
            public string Destination { get; init; } = string.Empty;

            [CommandOption("-d|--dry-run")]
            public bool DryRun { get; init; }
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                var (sv, sn) = CliHelpers.ParseVaultNs(settings.Source);
                var (dv, dn) = CliHelpers.ParseVaultNs(settings.Destination);
                ServiceFactory.Create().Push(sv, sn, dv, dn, settings.BuildUnlock(), settings.DryRun);
                var label = settings.DryRun ? "[yellow](dry run)[/]" : "[green]Done.[/]";
                AnsiConsole.MarkupLine($"Push {sv}:{sn} → {dv}:{dn} {label}");
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    // ---------------------------------------------------------------------- //
    //  pull
    // ---------------------------------------------------------------------- //

    internal sealed class PullCommand : Command<PullCommand.Settings>
    {
        public sealed class Settings : UnlockSettings
        {
            [CommandArgument(0, "<source>")]
            public string Source { get; init; } = string.Empty;

            [CommandArgument(1, "<destination>")]
            public string Destination { get; init; } = string.Empty;

            [CommandOption("-d|--dry-run")]
            public bool DryRun { get; init; }
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                var (sv, sn) = CliHelpers.ParseVaultNs(settings.Source);
                var (dv, dn) = CliHelpers.ParseVaultNs(settings.Destination);
                ServiceFactory.Create().Pull(sv, sn, dv, dn, settings.BuildUnlock(), settings.DryRun);
                var label = settings.DryRun ? "[yellow](dry run)[/]" : "[green]Done.[/]";
                AnsiConsole.MarkupLine($"Pull {sv}:{sn} → {dv}:{dn} {label}");
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }
}
