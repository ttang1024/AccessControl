using System.Text.Json;
using AccessControl.Application.Errors;
using AccessControl.Infrastructure.Storage;

namespace AccessControl.Infrastructure.Persistence;

/// <summary>
/// The rules <see cref="DocumentStore"/> enforces atomically at commit. They are the only check: services do not
/// look references up first, because the store reports the same errors (404 for a missing target, 409 for a target
/// still in use) and is the only place that cannot race. Properties are named with <c>nameof</c> on the records
/// in <c>Records.cs</c>, so renaming one is a compile error, not a constraint that silently matches nothing.
/// </summary>
internal static class StoreConstraints
{
    public static readonly UniqueIndex CardNumber = new(
        Collections.Credentials,
        Collections.CardNumberIndex,
        StorageJson.PropertyName(nameof(CredentialRecord.CardNumberDigest)),
        _ => ConflictException.DuplicateCardNumber());

    public static readonly IReadOnlyList<ForeignKey> ForeignKeys =
    [
        new(
            Collections.AccessGroups,
            Collections.Schedules,
            StorageJson.PropertyName(nameof(AccessGroupRecord.ScheduleId)),
            id => new NotFoundException(ResourceNames.Schedule, id),
            groups => ConflictException.InUseByGroups(ResourceNames.Schedule, NamesOf(groups))),
        new(
            Collections.AccessGroups,
            Collections.Doors,
            StorageJson.PropertyName(nameof(AccessGroupRecord.DoorIds)),
            id => new NotFoundException(ResourceNames.Door, id),
            groups => ConflictException.InUseByGroups(ResourceNames.Door, NamesOf(groups))),

        // Deleting a group removes its members in the same commit, so a remaining member joined concurrently.
        new(
            Collections.Cardholders,
            Collections.AccessGroups,
            StorageJson.PropertyName(nameof(CardholderRecord.AccessGroupIds)),
            id => new NotFoundException(ResourceNames.AccessGroup, id),
            _ => ConflictException.Concurrency()),

        // Cardholders are never deleted; kept so a credential can never point at a missing one.
        new(
            Collections.Credentials,
            Collections.Cardholders,
            StorageJson.PropertyName(nameof(CredentialRecord.CardholderId)),
            id => new NotFoundException(ResourceNames.Cardholder, id),
            _ => ConflictException.Concurrency()),
    ];

    private static List<string> NamesOf(IReadOnlyList<JsonElement> documents) =>
        documents
            .Select(d => d.TryGetProperty(StorageJson.PropertyName(nameof(AccessGroupRecord.Name)), out var name) ? name.GetString() : null)
            .OfType<string>()
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToList();
}
