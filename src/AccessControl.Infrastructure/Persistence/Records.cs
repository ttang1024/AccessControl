using System.Text.Json;
using AccessControl.Application.Abstractions;
using AccessControl.Domain.Access;
using AccessControl.Domain.Credentials;
using AccessControl.Domain.Doors;

namespace AccessControl.Infrastructure.Persistence;

// Persistence shapes, decoupled from domain types so the on-disk format only changes deliberately.
// Adding a nullable property is backwards compatible; renaming or removing one is not.

internal sealed record CardholderRecord(
    Guid Id,
    string FirstName,
    string LastName,
    string? EmployeeNumber,
    bool IsEnabled,
    DateTimeOffset? ValidFrom,
    DateTimeOffset? ValidUntil,
    List<Guid> AccessGroupIds);

internal sealed record CredentialRecord(
    Guid Id,
    Guid CardholderId,
    string CardNumber,
    CredentialStatus Status,
    DateTimeOffset IssuedAt,
    DateTimeOffset? ExpiresAt);

internal sealed record DoorRecord(Guid Id, string Name, string? Location, DoorMode Mode);

internal sealed record TimeWindowRecord(DayOfWeek Day, int StartMinute, int EndMinute);

internal sealed record ScheduleRecord(Guid Id, string Name, string TimeZoneId, List<TimeWindowRecord> Windows);

internal sealed record AccessGroupRecord(Guid Id, string Name, Guid ScheduleId, List<Guid> DoorIds);

internal sealed record ChangeRecord(
    Guid Id,
    DateTimeOffset OccurredAt,
    string Actor,
    Guid CommitId,
    string Collection,
    Guid EntityId,
    ChangeKind Kind,
    int Version,
    JsonElement? Before,
    JsonElement? After);

internal sealed record AccessEventRecord(
    Guid Id,
    DateTimeOffset OccurredAt,
    Guid DoorId,
    string CardNumber,
    Guid? CredentialId,
    Guid? CardholderId,
    bool Granted,
    AccessDecisionReason Reason);
