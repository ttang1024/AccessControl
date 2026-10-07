using System.Text.Json;

namespace AccessControl.Infrastructure.Storage;

internal enum AuditLineKind
{
    /// <summary><c>{seq, prev, hash, data}</c>.</summary>
    Chained,

    /// <summary>Written before hash chaining existed: the whole line is the payload.</summary>
    Legacy,

    /// <summary>Unreadable, e.g. torn by a crash.</summary>
    Corrupt,
}

/// <summary>One parsed line of a <see cref="ChainedJsonLinesLog"/> segment.</summary>
internal sealed record AuditLogLine(
    AuditLineKind Kind,
    string Location,
    long Sequence,
    string? Previous,
    string? Hash,
    JsonElement Data,
    string? RawData)
{
    public static AuditLogLine Corrupt(string location) => new(AuditLineKind.Corrupt, location, 0, null, null, default, null);

    /// <param name="includeRaw">Keep the payload's exact text, which hash verification needs.</param>
    public static AuditLogLine Parse(string path, int lineNumber, string text, bool includeRaw)
    {
        var location = $"{Path.GetFileName(path)} line {lineNumber}";
        try
        {
            using var document = JsonDocument.Parse(text);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return Corrupt(location);
            }

            if (root.TryGetProperty("data", out var data)
                && root.TryGetProperty("seq", out var seq)
                && root.TryGetProperty("prev", out var prev)
                && root.TryGetProperty("hash", out var hash))
            {
                return new AuditLogLine(
                    AuditLineKind.Chained, location, seq.GetInt64(), prev.GetString(), hash.GetString(),
                    data.Clone(), includeRaw ? data.GetRawText() : null);
            }

            return new AuditLogLine(AuditLineKind.Legacy, location, 0, null, null, root.Clone(), null);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException)
        {
            return Corrupt(location);
        }
    }
}
