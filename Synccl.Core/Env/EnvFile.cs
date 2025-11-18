using System.Text;
using System.Text.RegularExpressions;

namespace Synccl.Core.Env
{
    public static class EnvFile
    {
        private static readonly Regex KeyValueRegex =
            new(@"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)(\s*#.*)?$", RegexOptions.Compiled);

        public static List<EnvLine> Parse(string path)
        {
            var lines = new List<EnvLine>();

            foreach (var raw in File.ReadAllLines(path))
            {
                if (string.IsNullOrWhiteSpace(raw))
                {
                    lines.Add(new EnvBlank());
                    continue;
                }

                if (raw.TrimStart().StartsWith("#"))
                {
                    lines.Add(new EnvComment(raw));
                    continue;
                }

                var match = KeyValueRegex.Match(raw);
                if (match.Success)
                {
                    var key = match.Groups[1].Value;
                    var value = match.Groups[2].Value.Trim();
                    var comment = match.Groups[3].Success ? match.Groups[3].Value.Trim() : null;

                    lines.Add(new EnvKeyValue(key, value, raw, comment));
                }
                else
                {
                    lines.Add(new EnvComment(raw));
                }
            }

            return lines;
        }

        public static Dictionary<string, string> ToDictionary(List<EnvLine> lines)
        {
            return lines
                .OfType<EnvKeyValue>()
                .ToDictionary(x => x.Key, x => x.Value, StringComparer.OrdinalIgnoreCase);
        }

        public static List<EnvLine> ApplyValues(
            List<EnvLine> lines,
            Dictionary<string, string> updated)
        {
            var result = new List<EnvLine>();

            foreach (var line in lines)
            {
                if (line is EnvKeyValue kv && updated.TryGetValue(kv.Key, out var newVal))
                {
                    var raw = $"{kv.Key}={newVal}" + (kv.Comment != null ? $" {kv.Comment}" : "");
                    result.Add(new EnvKeyValue(kv.Key, newVal, raw, kv.Comment));
                    updated.Remove(kv.Key); 
                }
                else
                {
                    result.Add(line);
                }
            }

            foreach (var kv in updated)
            {
                result.Add(new EnvKeyValue(kv.Key, kv.Value, $"{kv.Key}={kv.Value}", null));
            }

            return result;
        }

        public static void Write(string path, List<EnvLine> lines)
        {
            var sb = new StringBuilder();

            foreach (var line in lines)
            {
                switch (line)
                {
                    case EnvKeyValue kv:
                        sb.AppendLine(kv.Raw);
                        break;
                    case EnvComment c:
                        sb.AppendLine(c.Text);
                        break;
                    case EnvBlank:
                        sb.AppendLine();
                        break;
                }
            }

            File.WriteAllText(path, sb.ToString());
        }
    }
}
