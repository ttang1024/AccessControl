using System.Text.Json;
using AccessControl.Application.Errors;
using AccessControl.Infrastructure.Storage;

namespace AccessControl.Infrastructure.Persistence;

/// <summary>
/// The rules <see cref="DocumentStore"/> enforces atomically at commit. Property names are those of the records in
/// <c>Records.cs</c> as serialised by <see cref="StorageJson"/> (camelCase).
/// </summary>
internal static class StoreConstraints
{
    public static readonly UniqueIndex CardNumber = new(
        Collections.Credentials,
        Collections.CardNumberIndex,
        body => body.TryGetProperty("cardNumber", out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null,
        ConflictException.DuplicateCardNumber);

    public static readonly IReadOnlyList<ForeignKey> ForeignKeys =
    [
        new(
            Collections.AccessGroups,
            Collections.Schedules,
            body => GuidsIn(body, "scheduleId"),
            id => new NotFoundException(ResourceNames.Schedule, id),
            groups => ConflictException.InUseByGroups(ResourceNames.Schedule, NamesOf(groups))),
        new(
            Collections.AccessGroups,
            Collections.Doors,
            body => GuidsIn(body, "doorIds"),
            id => new NotFoundException(ResourceNames.Door, id),
            groups => ConflictException.InUseByGroups(ResourceNames.Door, NamesOf(groups))),

        // Deleting a group removes its members in the same commit, so a remaining member joined concurrently.
        new(
            Collections.Cardholders,
            Collections.AccessGroups,
            body => GuidsIn(body, "accessGroupIds"),
            id => new NotFoundException(ResourceNames.AccessGroup, id),
            _ => ConflictException.Concurrency()),

        // Cardholders are never deleted; kept so a credential can never point at a missing one.
        new(
            Collections.Credentials,
            Collections.Cardholders,
            body => GuidsIn(body, "cardholderId"),
            id => new NotFoundException(ResourceNames.Cardholder, id),
            _ => ConflictException.Concurrency()),
    ];

    /// <summary>The ids in a Guid property or a Guid array property; nothing if it is missing or malformed.</summary>
    private static IEnumerable<Guid> GuidsIn(JsonElement body, string property)
    {
        if (!body.TryGetProperty(property, out var value))
        {
            yield break;
        }

        if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in value.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String && item.TryGetGuid(out var id))
                {
                    yield return id;
                }
            }
        }
        else if (value.ValueKind == JsonValueKind.String && value.TryGetGuid(out var id))
        {
            yield return id;
        }
    }

    private static List<string> NamesOf(IReadOnlyList<JsonElement> documents) =>
        documents
            .Select(d => d.TryGetProperty("name", out var name) ? name.GetString() : null)
            .OfType<string>()
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();
}
