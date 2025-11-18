using Spectre.Console;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Diff
{
    public record DiffResult(IReadOnlyList<SecretChange> Changes)
    {
        public IEnumerable<SecretChange> Adds => Changes.Where(c => c.Type == SecretChangeType.Add);
        public IEnumerable<SecretChange> Updates => Changes.Where(c => c.Type == SecretChangeType.Update);
        public IEnumerable<SecretChange> Deletes => Changes.Where(c => c.Type == SecretChangeType.Delete);
        public IEnumerable<SecretChange> NoChanges => Changes.Where(c => c.Type == SecretChangeType.NoChange);
        public IEnumerable<SecretChange> WithAdds => Changes.Where(c => c.Type != SecretChangeType.NoChange);

        public Table ToTable(string title, string sourceName, string targetName)
        {
            var table = new Table()
                .Border(TableBorder.Rounded)
                .Title($"[yellow]{title}[/]")
                .AddColumn("[grey]Key[/]")
                .AddColumn($"[grey]{sourceName}[/]")
                .AddColumn($"[grey]{targetName}[/]")
                .AddColumn("[grey]Change[/]");

            foreach (var change in this.Changes.Where(c => c.Type != SecretChangeType.NoChange))
            {
                var (key, oldVal, newVal, type) = (change.Key, change.OldValue, change.NewValue, change.Type);

                string symbol = type switch
                {
                    SecretChangeType.Add => "[green]+[/]",
                    SecretChangeType.Update => "[yellow]~[/]",
                    SecretChangeType.Delete => "[red]-[/]",
                    _ => ""
                };

                string desc = type switch
                {
                    SecretChangeType.Add => "[green]add[/]",
                    SecretChangeType.Update => "[yellow]update[/]",
                    SecretChangeType.Delete => "[red]remove[/]",
                    _ => ""
                };

                table.AddRow(
                    $"[white]{key}[/]",
                    newVal is null ? "[grey]—[/]" : $"[blue]{newVal}[/]",
                    oldVal is null ? "[grey]—[/]" : $"[blue]{oldVal}[/]",
                    $"{symbol} {desc}"
                );
            }

            return table;
        }
    }
}
