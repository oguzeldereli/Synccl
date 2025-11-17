using Spectre.Console;
using Spectre.Console.Cli;
using Synccl.Cli.Composition;
using Synccl.Cli.Helpers;
using Synccl.Cli.Settings;
using Synccl.Core.Keys;
using Synccl.Core.Vault;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Cli.Commands
{
    public class InitCommand : Command<InitCommandSettings>
    {
        public override int Execute(CommandContext context, InitCommandSettings settings, CancellationToken cancellationToken)
        {
            var path = settings.Path;

            var abortCheckResult = AbortChecks(path);
            if (abortCheckResult != 0)
            {
                return abortCheckResult;
            }

            var vaultResult = InitializeVault(path);
            if (vaultResult != 0)
            {
                return vaultResult;
            }

            var configResult = InitializeConfig(path);
            if (configResult != 0)
            {
                return configResult;
            }

            var exampleEnvResult = InitializeExampleEnvironmentFile(path);
            if (exampleEnvResult != 0)
            {
                return exampleEnvResult;
            }

            var gitignoreResult = AddEntriesToGitignore(path);
            if (gitignoreResult != 0)
            {
                return gitignoreResult;
            }

            AnsiConsole.MarkupLine($"[green]-[/] Initialized synccl in [blue]{path}[/]");
            return 0;
        }

        private int AbortChecks(string path)
        {
            if (!Directory.Exists(path))
            {
                AnsiConsole.MarkupLine($"[red]![/] The specified path [blue]{path}[/] does not exist - aborting");
                return 1;
            }

            var assembly = Assembly.GetExecutingAssembly();

            using (var stream = assembly.GetManifestResourceStream("Synccl.Cli.Templates.default-synccl.yaml"))
            {
                if (stream == null)
                {
                    AnsiConsole.MarkupLine("[red]![/] The default configuration file is missing - aborting");
                    return 1;
                }
            }

            using (var stream = assembly.GetManifestResourceStream("Synccl.Cli.Templates.default-env.example"))
            {
                if (stream == null)
                {
                    AnsiConsole.MarkupLine("[red]![/] The default example environment file is missing - aborting");
                    return 1;
                }
            }

            return 0;
        }
        private int InitializeVault(string path)
        {
            var syncclDir = Path.Combine(path, ".synccl");
            var syncclKeysDir = Path.Combine(syncclDir, "Keys");
            var syncclDevicesDir = Path.Combine(syncclDir, "Devices");
            var vaultIdPath = Path.Combine(syncclDir, "id");

            if (!Directory.Exists(syncclDir))
            {
                Directory.CreateDirectory(syncclDir);
                File.SetAttributes(syncclDir, File.GetAttributes(syncclDir) | FileAttributes.Hidden);
                AnsiConsole.MarkupLine($"[green]-[/] Created directory [blue]{syncclDir}[/]");
            }

            if (!Directory.Exists(syncclKeysDir))
            {
                Directory.CreateDirectory(syncclKeysDir);
            }

            if (!Directory.Exists(syncclDevicesDir))
            {
                Directory.CreateDirectory(syncclKeysDir);
            }

            if (File.Exists(vaultIdPath))
            {
                AnsiConsole.MarkupLine("[red]Vault already exists in this directory.[/]");
                AnsiConsole.MarkupLine("Run: [yellow]synccl destroy[/] first if you want to reset.");
                return -1;
            }

            var vaultId = Guid.NewGuid().ToString("D");
            File.WriteAllText(vaultIdPath, vaultId);

            var service = ServiceFactory.CreateVaultService(path);
            var vaultResult = service.InitVault();
            if (vaultResult.IsFailure)
            {
                AnsiConsole.MarkupLine(vaultResult.ErrorMessage!);
                return 1;
            }

            var vault = vaultResult.Data!;
            var saveResult = service.Save(vault);
            if (saveResult.IsFailure)
            {
                AnsiConsole.MarkupLine(saveResult.ErrorMessage!);
                return 1;
            }

            AnsiConsole.MarkupLine($"[green]✔[/] Vault initialized with ID [blue]{vaultId}[/]");
            return 0;
        }



        private int InitializeConfig(string path)
        {
            var configFilePath = Path.Combine(path, "synccl.yaml");
            if (File.Exists(configFilePath))
            {
                AnsiConsole.MarkupLine($"[yellow]![/] A synccl configuration file already exists in [blue]{path}[/] - skipping");
                return 0;
            }
                
            var assembly = Assembly.GetExecutingAssembly();
            using var stream = assembly.GetManifestResourceStream("Synccl.Cli.Templates.default-synccl.yaml");
            if (stream == null)
            {
                AnsiConsole.MarkupLine("[red]![/] The default configuration file is missing - aborting");
                return 1;
            }

            using var reader = new StreamReader(stream);
            var yamlContent = reader.ReadToEnd();
            yamlContent = yamlContent.ReplaceLineEndings();
            File.WriteAllText(configFilePath, yamlContent);

            return 0;
        }

        private int InitializeExampleEnvironmentFile(string path)
        {
            var envFilePath = Path.Combine(path, ".env.example");
            if (File.Exists(envFilePath))
            {
                AnsiConsole.MarkupLine($"[yellow]![/] An example environment file already exists in [blue]{path}[/] - skipping");
                return 0;
            }

            var alreadyExistingEnvFiles = Directory.GetFiles(path, "*.env", SearchOption.TopDirectoryOnly);
            if (alreadyExistingEnvFiles.Length < 1)
            {
                var assembly = Assembly.GetExecutingAssembly();
                using var stream = assembly.GetManifestResourceStream("Synccl.Cli.Templates.default-env.example");
                if (stream == null)
                {
                    AnsiConsole.MarkupLine("[red]![/] The default example environment file is missing - aborting");
                    return 1;
                }

                using var reader = new StreamReader(stream);
                var envContent = reader.ReadToEnd();
                envContent = envContent.ReplaceLineEndings();
                File.WriteAllText(envFilePath, envContent);
                return 0;
            }

            var envVariables = new HashSet<string>();
            foreach (var envFile in alreadyExistingEnvFiles)
            {
                var lines = File.ReadAllLines(envFile);
                foreach (var line in lines)
                {
                    var trimmedLine = line.Trim();
                    if (string.IsNullOrEmpty(trimmedLine) || trimmedLine.StartsWith("#"))
                    {
                        continue;
                    }
                    var separatorIndex = trimmedLine.IndexOf('=');
                    if (separatorIndex > 0)
                    {
                        var variableName = trimmedLine.Substring(0, separatorIndex).Trim();
                        envVariables.Add(variableName);
                    }
                }
            }

            var sb = new StringBuilder();
            foreach (var variable in envVariables)
            {
                sb.AppendLine($"{variable}=");
            }

            File.WriteAllText(envFilePath, sb.ToString());
            return 0;
        }

        private int AddEntriesToGitignore(string path)
        {
            var gitignorePath = Path.Combine(path, ".gitignore");
            var entriesToAdd = new List<string>
            {
                ".synccl/",
                ".env",
            };

            HashSet<string> existingEntries = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (File.Exists(gitignorePath))
            {
                var existingLines = File.ReadAllLines(gitignorePath);
                foreach (var line in existingLines)
                {
                    existingEntries.Add(line.Trim());
                }
            }

            var encoding = DetectEncoding(gitignorePath);
            using var writer = new StreamWriter(gitignorePath, append: true, encoding); 
            writer.WriteLine();
            foreach (var entry in entriesToAdd)
            {
                if (!existingEntries.Contains(entry))
                {
                    writer.WriteLine(entry);
                }
            }

            AnsiConsole.MarkupLine($"[green]-[/] Added .synccl/ and .env to [blue].gitignore[/]");
            return 0;
        }

        private Encoding DetectEncoding(string filePath)
        {
            using var reader = new StreamReader(filePath, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            reader.Peek(); 
            return reader.CurrentEncoding;
        }
    }
}
