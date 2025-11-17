using Spectre.Console;
using Spectre.Console.Cli;
using System.ComponentModel;
using Synccl.Cli.Config;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;
using Synccl.Cli.Settings.Remote.Add;

public class RemoteAddS3Command : Command<RemoteAddS3CommandSettings>
{
    public override int Execute(CommandContext context, RemoteAddS3CommandSettings settings, CancellationToken cancellationToken)
    {
        var name = string.IsNullOrWhiteSpace(settings.Name) ? "origin" : settings.Name;
        var path = Directory.GetCurrentDirectory();
        var config = ConfigLoader.TryLoadConfig(path);

        if (config.Remotes.Any(x => x.Name == name))
        {
            var overwrite = AnsiConsole.Confirm($"[yellow]Remote with name '{name}' already exists. Overwrite?[/]");
            if (!overwrite)
            {
                AnsiConsole.MarkupLine("[grey]Canceled[/]");
                return 0;
            }
        }

        var bucket = settings.Bucket ?? AnsiConsole.Prompt(
            new TextPrompt<string>("S3 Bucket name:")
                .Validate(x => string.IsNullOrWhiteSpace(x) ? ValidationResult.Error("Bucket required") : ValidationResult.Success()));

        var region = settings.Region ?? AnsiConsole.Prompt(
            new TextPrompt<string>("AWS Region (e.g. us-east-1):")
                .Validate(x => string.IsNullOrWhiteSpace(x) ? ValidationResult.Error("Region required") : ValidationResult.Success()));

        var prefix = settings.Prefix ?? AnsiConsole.Prompt(
            new TextPrompt<string>("Prefix (project folder in bucket):")
                .DefaultValue("synccl"));

        var profile = settings.Profile ?? AnsiConsole.Prompt(
            new TextPrompt<string>("AWS Profile (optional):")
                .AllowEmpty());

        var existingNameRemote = config.Remotes.FirstOrDefault(x => x?.Name == name);
        if (existingNameRemote != null)
        {
            config.Remotes.Remove(existingNameRemote);
        }

        config.Remotes.Add(new RemoteConfig
        {
            Name = name,
            Type = "s3",
            Bucket = bucket,
            Region = region,
            Prefix = prefix,
            Profile = string.IsNullOrWhiteSpace(profile) ? null : profile
        });

        ConfigLoader.SaveConfig(path, config);

        AnsiConsole.MarkupLine("[green]+ S3 remote added[/]");
        return 0;
    }
}
