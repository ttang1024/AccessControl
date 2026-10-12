using AccessControl.Domain.Access;
using AccessControl.Domain.AccessGroups;
using AccessControl.Domain.Cardholders;
using AccessControl.Domain.Credentials;
using AccessControl.Domain.Doors;
using AccessControl.Domain.Schedules;

namespace AccessControl.Application.Abstractions;

/// <summary>
/// Repository over one aggregate type. Changes are staged and only become durable
/// when <see cref="IUnitOfWork.CommitAsync"/> succeeds. Implementations hand out a fresh
/// instance per load, so mutating an aggregate and then not committing has no effect.
/// Lists are filtered, ordered and paged by the repository, so an adapter can push them down to its database.
/// </summary>
public interface IRepository<TAggregate>
    where TAggregate : class
{
    Task<TAggregate?> GetAsync(Guid id, CancellationToken cancellationToken);

    /// <summary>Loads the aggregates that exist among <paramref name="ids"/>; missing ids are skipped.</summary>
    Task<IReadOnlyList<TAggregate>> GetManyAsync(IEnumerable<Guid> ids, CancellationToken cancellationToken);

    /// <summary>Stages a new aggregate. Committing fails if one with the same id already exists.</summary>
    void Add(TAggregate aggregate);

    /// <summary>
    /// Stages changes to an aggregate loaded in this unit of work. Committing fails with a
    /// concurrency conflict if someone else committed a change to it after it was loaded.
    /// If the aggregate is unchanged, nothing is written and no change-trail entry is recorded.
    /// </summary>
    void Update(TAggregate aggregate);

    /// <summary>Stages deletion of an aggregate loaded in this unit of work.</summary>
    void Remove(TAggregate aggregate);

    /// <summary>
    /// The aggregate's version as loaded, or as last committed, in this unit of work. It increases with every
    /// committed change and is the concurrency token clients send back (HTTP <c>ETag</c> / <c>If-Match</c>).
    /// </summary>
    int VersionOf(TAggregate aggregate);
}

public interface ICardholderRepository : IRepository<Cardholder>
{
    /// <summary>
    /// Case-insensitive match on first name, last name or employee number, optionally only members of one access
    /// group; ordered by last name, first name.
    /// </summary>
    Task<PagedResult<Cardholder>> SearchAsync(string? text, Guid? accessGroupId, PageRequest page, CancellationToken cancellationToken);

    /// <summary>Every member of a group, unpaged: for removing them all when the group is deleted.</summary>
    Task<IReadOnlyList<Cardholder>> ListByAccessGroupAsync(Guid accessGroupId, CancellationToken cancellationToken);
}

public interface ICredentialRepository : IRepository<Credential>
{
    Task<Credential?> FindByCardAsync(CardFingerprint card, CancellationToken cancellationToken);

    /// <summary>A cardholder's credentials, oldest issued first. A handful per person, so unpaged.</summary>
    Task<IReadOnlyList<Credential>> ListByCardholderAsync(Guid cardholderId, CancellationToken cancellationToken);
}

public interface IDoorRepository : IRepository<Door>
{
    /// <summary>Case-insensitive match on name or location; ordered by name.</summary>
    Task<PagedResult<Door>> SearchAsync(string? text, PageRequest page, CancellationToken cancellationToken);

    /// <summary>Every door, unpaged: for site-wide operations such as a lockdown.</summary>
    Task<IReadOnlyList<Door>> ListAllAsync(CancellationToken cancellationToken);
}

public interface IScheduleRepository : IRepository<Schedule>
{
    /// <summary>Case-insensitive match on name; ordered by name.</summary>
    Task<PagedResult<Schedule>> SearchAsync(string? text, PageRequest page, CancellationToken cancellationToken);
}

public interface IAccessGroupRepository : IRepository<AccessGroup>
{
    /// <summary>Case-insensitive match on name; ordered by name.</summary>
    Task<PagedResult<AccessGroup>> SearchAsync(string? text, PageRequest page, CancellationToken cancellationToken);
}

/// <summary>Atomically persists every change staged through the repositories in the current scope.</summary>
public interface IUnitOfWork
{
    /// <exception cref="Errors.ConflictException">A concurrent change, uniqueness violation or a deleted target still in use prevented the commit; nothing was written.</exception>
    /// <exception cref="Errors.NotFoundException">The commit adds a reference to something that does not exist; nothing was written.</exception>
    Task CommitAsync(CancellationToken cancellationToken);
}

/// <summary>Append-only store for the access audit trail.</summary>
public interface IAccessEventLog
{
    Task AppendAsync(AccessEvent accessEvent, CancellationToken cancellationToken);

    /// <summary>Returns matching events, newest first.</summary>
    Task<PagedResult<AccessEvent>> QueryAsync(AccessEventFilter filter, PageRequest page, CancellationToken cancellationToken);
}

public sealed record AccessEventFilter(
    Guid? DoorId = null,
    Guid? CardholderId = null,
    bool? Granted = null,
    DateTimeOffset? From = null,
    DateTimeOffset? To = null)
{
    public bool Matches(AccessEvent e) =>
        (DoorId is null || e.DoorId == DoorId)
        && (CardholderId is null || e.CardholderId == CardholderId)
        && (Granted is null || e.Granted == Granted)
        && (From is null || e.OccurredAt >= From)
        && (To is null || e.OccurredAt < To);
}
