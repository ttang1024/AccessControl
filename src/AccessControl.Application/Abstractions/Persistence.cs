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
    /// </summary>
    void Update(TAggregate aggregate);

    /// <summary>Stages deletion of an aggregate loaded in this unit of work.</summary>
    void Remove(TAggregate aggregate);
}

public interface ICardholderRepository : IRepository<Cardholder>
{
    /// <summary>Case-insensitive match on first name, last name or employee number; ordered by last, first name.</summary>
    Task<PagedResult<Cardholder>> SearchAsync(string? text, PageRequest page, CancellationToken cancellationToken);

    Task<IReadOnlyList<Cardholder>> ListByAccessGroupAsync(Guid accessGroupId, CancellationToken cancellationToken);
}

public interface ICredentialRepository : IRepository<Credential>
{
    Task<Credential?> FindByCardNumberAsync(CardNumber cardNumber, CancellationToken cancellationToken);

    Task<IReadOnlyList<Credential>> ListByCardholderAsync(Guid cardholderId, CancellationToken cancellationToken);
}

public interface IDoorRepository : IRepository<Door>
{
    Task<IReadOnlyList<Door>> ListAsync(CancellationToken cancellationToken);
}

public interface IScheduleRepository : IRepository<Schedule>
{
    Task<IReadOnlyList<Schedule>> ListAsync(CancellationToken cancellationToken);
}

public interface IAccessGroupRepository : IRepository<AccessGroup>
{
    Task<IReadOnlyList<AccessGroup>> ListAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<AccessGroup>> ListByDoorAsync(Guid doorId, CancellationToken cancellationToken);

    Task<IReadOnlyList<AccessGroup>> ListByScheduleAsync(Guid scheduleId, CancellationToken cancellationToken);
}

/// <summary>Atomically persists every change staged through the repositories in the current scope.</summary>
public interface IUnitOfWork
{
    /// <exception cref="Errors.ConflictException">A concurrent change or uniqueness violation prevented the commit; nothing was written.</exception>
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
