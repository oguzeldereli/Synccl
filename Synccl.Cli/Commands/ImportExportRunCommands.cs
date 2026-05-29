using Spectre.Console;
using Spectre.Console.Cli;
using System.ComponentModel;

namespace Synccl.Cli.Commands
{
    // ---------------------------------------------------------------------- //
    //  import
    // ---------------------------------------------------------------------- //

    internal sealed class ImportCommand : Command<ImportCommand.Settings>
    {
        public sealed class Settings : UnlockSettings
        {
            [CommandArgument(0, "<vault:ns>")]
            public string Target { get; init; } = string.Empty;

            [CommandArgument(1, "<path>")]
            [Description("Path to the file to import")]
            public string FilePath { get; init; } = string.Empty;

            [CommandOption("-f|--format")]
            [Description("File format: env (default) or csv")]
            public string Format { get; init; } = "env";
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                var (vault, ns) = CliHelpers.ParseVaultNs(settings.Target);
                ServiceFactory.Create().ImportFromFile(
                    vault, ns, settings.FilePath, settings.Format, settings.BuildUnlock());
                AnsiConsole.MarkupLine($"[green]Imported from [bold]{settings.FilePath}[/] into {vault}:{ns}.[/]");
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    // ---------------------------------------------------------------------- //
    //  export
    // ---------------------------------------------------------------------- //

    internal sealed class ExportCommand : Command<ExportCommand.Settings>
    {
        public sealed class Settings : UnlockSettings
        {
            [CommandArgument(0, "<vault:ns>")]
            public string Target { get; init; } = string.Empty;

            [CommandArgument(1, "<path>")]
            [Description("Destination file path")]
            public string FilePath { get; init; } = string.Empty;

            [CommandOption("-f|--format")]
            [Description("File format: env (default) or csv")]
            public string Format { get; init; } = "env";
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                var (vault, ns) = CliHelpers.ParseVaultNs(settings.Target);
                ServiceFactory.Create().ExportToFile(
                    vault, ns, settings.FilePath, settings.Format, settings.BuildUnlock());
                AnsiConsole.MarkupLine($"[green]Exported {vault}:{ns} to [bold]{settings.FilePath}[/].[/]");
                return 0;
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }

    // ---------------------------------------------------------------------- //
    //  run
    // ---------------------------------------------------------------------- //

    internal sealed class RunCommand : Command<RunCommand.Settings>
    {
        public sealed class Settings : UnlockSettings
        {
            [CommandArgument(0, "<vault:ns>")]
            public string Target { get; init; } = string.Empty;

            [CommandArgument(1, "<executable>")]
            [Description("Path to executable")]
            public string Executable { get; init; } = string.Empty;

            [CommandArgument(2, "[args]")]
            [Description("Arguments to pass to the executable")]
            public string[] Args { get; init; } = [];
        }

        protected override int Execute(CommandContext context, Settings settings, CancellationToken cancellationToken)
        {
            try
            {
                var (vault, ns) = CliHelpers.ParseVaultNs(settings.Target);
                return ServiceFactory.Create().RunProcess(
                    vault, ns, settings.Executable, settings.Args, settings.BuildUnlock());
            }
            catch (Exception ex) { return CliHelpers.HandleError(ex); }
        }
    }
}
