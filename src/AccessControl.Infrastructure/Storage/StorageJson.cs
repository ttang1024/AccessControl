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
}
