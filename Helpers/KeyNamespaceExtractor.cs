namespace Synccl.Cli.Helpers
{
    public static class KeyNamespaceExtractor
    {
        public static (string Namespace, string Key) Extract(
            string rawKey,
            string? namespaceOption,
            string defaultNamespace = "default")
        {
            if (!string.IsNullOrWhiteSpace(namespaceOption))
            {
                var parts = rawKey.Split(new[] { "::" }, 2, StringSplitOptions.None);
                var keyOnly = parts.Length == 2 ? parts[1] : rawKey;
                return (namespaceOption, keyOnly);
            }

            var split = rawKey.Split(new[] { "::" }, 2, StringSplitOptions.None);
            if (split.Length == 2)
                return (split[0], split[1]);

            return (defaultNamespace, rawKey);
        }
    }
}
