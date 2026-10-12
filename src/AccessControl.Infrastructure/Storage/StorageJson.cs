using System.Text.Json;
using System.Text.Json.Serialization;

namespace AccessControl.Infrastructure.Storage;

internal static class StorageJson
{
    /// <summary>On-disk format. Enums are stored by name so reordering an enum never corrupts data.</summary>
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>
    /// The serialised name of a record property, for code that reads stored JSON directly (e.g. store constraints).
    /// Pass <c>nameof(Record.Property)</c>, so renaming the property is a compile error rather than a silent mismatch.
    /// </summary>
    public static string PropertyName(string clrName) => Options.PropertyNamingPolicy!.ConvertName(clrName);
}
