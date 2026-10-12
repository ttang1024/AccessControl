using System.Text.Json;
using AccessControl.Application.Abstractions;
using AccessControl.Domain.Access;
using AccessControl.Domain.Credentials;
using AccessControl.Domain.Doors;

namespace AccessControl.Infrastructure.Persistence;

// Persistence shapes, decoupled from domain and application types so the on-disk format only changes deliberately.
// Records are immutable (read-only collections): materialised records are cached per stored document and shared
// between requests (see DocumentSession).
//
// Store records (aggregates in store.json): adding a nullable property is compatible; renaming or removing one is a
// format change (bump DocumentStore.FormatVersion and convert existing data).
//
// Audit records (ChangeRecord, AccessEventRecord: lines in *.jsonl): the hash chain forbids rewriting a line, so old
// entries can never be converted and must stay readable for as long as retention keeps them. Only add nullable
// properties; never rename or remove one.

internal sealed record CardholderRecord(
    Guid Id,
    string FirstName,
    string LastName,
    string? EmployeeNumber,
    bool IsEnabled,
    DateTimeOffset? ValidFrom,
    DateTimeOffset? ValidUntil,
    IReadOnlyList<Guid> AccessGroupIds);

/// <param name="CardNumberDigest">Keyed digest of the card number; the number itself is never stored.</param>
/// <param name="CardNumberHint">The last digits that may be shown.</param>
internal sealed record CredentialRecord(
    Guid Id,
    Guid CardholderId,
    string CardNumberDigest,
    string CardNumberHint,
    CredentialStatus Status,
    DateTimeOffset IssuedAt,
    DateTimeOffset? ExpiresAt);

internal sealed record DoorRecord(Guid Id, string Name, string? Location, DoorMode Mode);

internal sealed record TimeWindowRecord(DayOfWeek Day, int StartMinute, int EndMinute);

internal sealed record ScheduleRecord(Guid Id, string Name, string TimeZoneId, IReadOnlyList<TimeWindowRecord> Windows);

internal sealed record AccessGroupRecord(Guid Id, string Name, Guid ScheduleId, IReadOnlyList<Guid> DoorIds, bool IsRestricted);

/// <summary>Audit record: one line of changes*.jsonl. See the rules for audit records above.</summary>
/// <param name="CommitSize">Entries written by the same commit, so replay can tell a commit cut off by a crash.</param>
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
    JsonElement? After,
    int CommitSize);

/// <summary>Audit record: one line of access-events*.jsonl. See the rules for audit records above.</summary>
/// <param name="CardNumberDigest">The presented card's fingerprint digest; absent for unreadable input.</param>
/// <param name="CardDisplay">Masked display form.</param>
internal sealed record AccessEventRecord(
    Guid Id,
    DateTimeOffset OccurredAt,
    Guid DoorId,
    string? CardNumberDigest,
    string CardDisplay,
    Guid? CredentialId,
    Guid? CardholderId,
    bool Granted,
    AccessDecisionReason Reason);
