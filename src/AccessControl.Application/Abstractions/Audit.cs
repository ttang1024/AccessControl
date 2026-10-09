using System.Text.Json;

namespace AccessControl.Application.Abstractions;

/// <summary>
/// Who is performing the current command. Recorded with every committed configuration change.
/// The host supplies it (the API uses the authenticated key's name); the default is <see cref="SystemActor"/>.
/// </summary>
public interface IActorContext
{
    string Actor { get; }
}

/// <summary>Used outside a request, e.g. maintenance code or tests that do not care who acted.</summary>
public sealed class SystemActor : IActorContext
{
    public string Actor => "system";
}

public enum ChangeKind
{
    Created,
    Updated,
    Deleted,
}

/// <summary>
/// One aggregate changed by one commit. <see cref="Before"/> and <see cref="After"/> are the persisted
/// documents (<c>null</c> for a create or delete respectively). Entries from the same commit share a
/// <see cref="CommitId"/>.
/// </summary>
public sealed record ChangeAuditEntry(
    Guid Id,
    DateTimeOffset OccurredAt,
    string Actor,
    Guid CommitId,
    string EntityType,
    Guid EntityId,
    ChangeKind Kind,
    int Version,
    JsonElement? Before,
    JsonElement? After);

public sealed record ChangeAuditFilter(
    string? EntityType = null,
    Guid? EntityId = null,
    string? Actor = null,
    DateTimeOffset? From = null,
    DateTimeOffset? To = null)
{
    public bool Matches(ChangeAuditEntry e) =>
        (EntityType is null || string.Equals(e.EntityType, EntityType, StringComparison.OrdinalIgnoreCase))
        && (EntityId is null || e.EntityId == EntityId)
        && (Actor is null || string.Equals(e.Actor, Actor, StringComparison.Ordinal))
        && (From is null || e.OccurredAt >= From)
        && (To is null || e.OccurredAt < To);
}

/// <summary>
/// Append-only record of configuration changes. Entries are written by the unit of work as part of
/// every commit, before the change becomes visible, so a change can never exist without its entry.
/// </summary>
public interface IChangeAuditLog
{
    /// <summary>Returns matching entries, newest first.</summary>
    Task<PagedResult<ChangeAuditEntry>> QueryAsync(ChangeAuditFilter filter, PageRequest page, CancellationToken cancellationToken);
}

/// <summary>Outcome of checking one audit log's hash chain.</summary>
/// <param name="Log">Which log (e.g. <c>access-events</c>, <c>changes</c>).</param>
/// <param name="IsIntact">False if any entry was altered, removed, reordered or inserted.</param>
/// <param name="Entries">Chained entries checked.</param>
/// <param name="SkippedLines">Unreadable lines (e.g. torn by a crash). The chain is still checked across them.</param>
/// <param name="FirstSequence">Sequence number of the oldest chained entry still on disk.</param>
/// <param name="LastSequence">Sequence number of the newest chained entry.</param>
/// <param name="LastHash">
/// Hash of the newest entry. The chain cannot prove that its newest entries were not removed while the service was
/// stopped, so monitoring should store (<paramref name="LastSequence"/>, <paramref name="LastHash"/>) off this host
/// and alert if a later report has a lower sequence or a different hash for the same sequence.
/// </param>
/// <param name="Problem">Where and why verification failed, when <paramref name="IsIntact"/> is false.</param>
public sealed record AuditChainReport(
    string Log,
    bool IsIntact,
    long Entries,
    long SkippedLines,
    long? FirstSequence,
    long? LastSequence,
    string? LastHash,
    string? Problem);

public interface IAuditIntegrity
{
    Task<IReadOnlyList<AuditChainReport>> VerifyAsync(CancellationToken cancellationToken);
}
