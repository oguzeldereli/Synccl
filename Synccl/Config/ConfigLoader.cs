using System;
using System.IO;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Synccl.Cli.Config;

public static class ConfigLoader
{
    private static readonly string ConfigFileName = "synccl.yaml";

    public static SyncclConfig Load(string? root = null)
    {
        var path = root ?? Environment.CurrentDirectory;
        var fullPath = Path.Combine(path, ConfigFileName);

        if (!File.Exists(fullPath))
            throw new InvalidOperationException($"synccl.yaml not found in {path}");

        var yaml = File.ReadAllText(fullPath);

        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(CamelCaseNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        try
        {
            var config = deserializer.Deserialize<SyncclConfig>(yaml);
            return config ?? new SyncclConfig();
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Invalid synccl.yaml: {ex.Message}");
        }
    }

    public static SyncclConfig TryLoadConfig(string path)
    {
        try { return Load(path); }
        catch { return new SyncclConfig(); }
    }

    public static void SaveConfig(string path, SyncclConfig config)
    {
        var serializer = new SerializerBuilder()
            .WithNamingConvention(CamelCaseNamingConvention.Instance)
            .WithIndentedSequences()
            .Build();

        var yaml = serializer.Serialize(config);
        File.WriteAllText(Path.Combine(path, "synccl.yaml"), yaml);
    }
}
