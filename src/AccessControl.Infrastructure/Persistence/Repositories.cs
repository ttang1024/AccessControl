using AccessControl.Application.Abstractions;
using AccessControl.Domain.AccessGroups;
using AccessControl.Domain.Cardholders;
using AccessControl.Domain.Common;
using AccessControl.Domain.Credentials;
using AccessControl.Domain.Doors;
using AccessControl.Domain.Schedules;
using AccessControl.Infrastructure.Storage;

namespace AccessControl.Infrastructure.Persistence;

internal static class Collections
{
    public const string Cardholders = "cardholders";
    public const string Credentials = "credentials";
    public const string Doors = "doors";
    public const string Schedules = "schedules";
    public const string AccessGroups = "accessGroups";

    public const string CardNumberIndex = "credentials.cardNumber";
}

/// <summary>
/// Maps one aggregate type to one collection. Subclasses supply the mapping only.
/// Reads are served from the session's in-memory snapshot, so the async port methods complete synchronously;
/// the signatures are async so that a database-backed implementation can replace this one unchanged.
/// </summary>
internal abstract class DocumentRepository<TAggregate, TRecord>(
    DocumentSession session, string collection, Func<TAggregate, Guid> idOf)
    : IRepository<TAggregate>
    where TAggregate : class
    where TRecord : class
{
    protected DocumentSession Session { get; } = session;

    public Task<TAggregate?> GetAsync(Guid id, CancellationToken cancellationToken) =>
        Task.FromResult(Session.Load<TRecord>(collection, id) is { } record ? Rehydrate(record) : null);

    public Task<IReadOnlyList<TAggregate>> GetManyAsync(IEnumerable<Guid> ids, CancellationToken cancellationToken)
    {
        IReadOnlyList<TAggregate> result = ids
            .Distinct()
            .Select(id => Session.Load<TRecord>(collection, id))
            .OfType<TRecord>()
            .Select(Rehydrate)
            .ToList();
        return Task.FromResult(result);
    }

    public void Add(TAggregate aggregate) => Session.Insert(collection, idOf(aggregate), ToRecord(aggregate));

    public void Update(TAggregate aggregate) => Session.Replace(collection, idOf(aggregate), ToRecord(aggregate));

    public void Remove(TAggregate aggregate) => Session.Delete(collection, idOf(aggregate));

    public Task<IReadOnlyList<TAggregate>> ListAsync(CancellationToken cancellationToken) => WhereAsync(_ => true);

    protected Task<IReadOnlyList<TAggregate>> WhereAsync(Func<TRecord, bool> predicate)
    {
        IReadOnlyList<TAggregate> result = Session.Query<TRecord>(collection).Where(predicate).Select(Rehydrate).ToList();
        return Task.FromResult(result);
    }

    protected IEnumerable<TAggregate> All() => Session.Query<TRecord>(collection).Select(Rehydrate);

    /// <summary>
    /// Maps a stored record to its aggregate. An aggregate that rejects its stored state means the data (or the host,
    /// e.g. a missing time-zone database) is broken: that is a server fault, not a client's invalid request, so it is
    /// raised as <see cref="InvalidDataException"/> (500) instead of the domain's validation error (400).
    /// </summary>
    protected TAggregate Rehydrate(TRecord record)
    {
        try
        {
            return ToAggregate(record);
        }
        catch (DomainException ex)
        {
            throw new InvalidDataException($"Stored {collection} document is invalid ({ex.Code}): {ex.Message}", ex);
        }
    }

    protected abstract TRecord ToRecord(TAggregate aggregate);

    protected abstract TAggregate ToAggregate(TRecord record);
}

internal sealed class CardholderRepository(DocumentSession session)
    : DocumentRepository<Cardholder, CardholderRecord>(session, Collections.Cardholders, a => a.Id), ICardholderRepository
{
    public Task<PagedResult<Cardholder>> SearchAsync(string? text, PageRequest page, CancellationToken cancellationToken)
    {
        var term = text?.Trim();
        var matches = All()
            .Where(c => string.IsNullOrEmpty(term)
                || c.FirstName.Contains(term, StringComparison.OrdinalIgnoreCase)
                || c.LastName.Contains(term, StringComparison.OrdinalIgnoreCase)
                || (c.EmployeeNumber?.Contains(term, StringComparison.OrdinalIgnoreCase) ?? false))
            .OrderBy(c => c.LastName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(c => c.FirstName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(c => c.Id);
        return Task.FromResult(PagedResult.Create(matches, page));
    }

    public Task<IReadOnlyList<Cardholder>> ListByAccessGroupAsync(Guid accessGroupId, CancellationToken cancellationToken) =>
        WhereAsync(r => r.AccessGroupIds.Contains(accessGroupId));

    protected override CardholderRecord ToRecord(Cardholder c) =>
        new(c.Id, c.FirstName, c.LastName, c.EmployeeNumber, c.IsEnabled, c.ValidFrom, c.ValidUntil,
            c.AccessGroupIds.Order().ToList());

    protected override Cardholder ToAggregate(CardholderRecord r) =>
        Cardholder.Rehydrate(r.Id, r.FirstName, r.LastName, r.EmployeeNumber, r.IsEnabled, r.ValidFrom, r.ValidUntil,
            r.AccessGroupIds ?? []);
}

internal sealed class CredentialRepository(DocumentSession session)
    : DocumentRepository<Credential, CredentialRecord>(session, Collections.Credentials, a => a.Id), ICredentialRepository
{
    public Task<Credential?> FindByCardNumberAsync(CardNumber cardNumber, CancellationToken cancellationToken) =>
        Task.FromResult(
            Session.LoadByKey<CredentialRecord>(Collections.Credentials, Collections.CardNumberIndex, cardNumber.Value)
                is { } record
                ? Rehydrate(record)
                : null);

    public Task<IReadOnlyList<Credential>> ListByCardholderAsync(Guid cardholderId, CancellationToken cancellationToken) =>
        WhereAsync(r => r.CardholderId == cardholderId);

    protected override CredentialRecord ToRecord(Credential c) =>
        new(c.Id, c.CardholderId, c.CardNumber.Value, c.Status, c.IssuedAt, c.ExpiresAt);

    protected override Credential ToAggregate(CredentialRecord r) =>
        Credential.Rehydrate(r.Id, r.CardholderId, CardNumber.Parse(r.CardNumber), r.Status, r.IssuedAt, r.ExpiresAt);
}

internal sealed class DoorRepository(DocumentSession session)
    : DocumentRepository<Door, DoorRecord>(session, Collections.Doors, a => a.Id), IDoorRepository
{
    protected override DoorRecord ToRecord(Door d) => new(d.Id, d.Name, d.Location, d.Mode);

    protected override Door ToAggregate(DoorRecord r) => Door.Rehydrate(r.Id, r.Name, r.Location, r.Mode);
}

internal sealed class ScheduleRepository(DocumentSession session)
    : DocumentRepository<Schedule, ScheduleRecord>(session, Collections.Schedules, a => a.Id), IScheduleRepository
{
    protected override ScheduleRecord ToRecord(Schedule s) =>
        new(s.Id, s.Name, s.TimeZone.Id,
            s.Windows.Select(w => new TimeWindowRecord(w.Day, (int)w.Start.TotalMinutes, (int)w.End.TotalMinutes)).ToList());

    protected override Schedule ToAggregate(ScheduleRecord r) =>
        Schedule.Rehydrate(r.Id, r.Name, r.TimeZoneId,
            (r.Windows ?? []).Select(w => WeeklyTimeWindow.Create(
                w.Day, TimeSpan.FromMinutes(w.StartMinute), TimeSpan.FromMinutes(w.EndMinute))));
}

internal sealed class AccessGroupRepository(DocumentSession session)
    : DocumentRepository<AccessGroup, AccessGroupRecord>(session, Collections.AccessGroups, a => a.Id), IAccessGroupRepository
{
    public Task<IReadOnlyList<AccessGroup>> ListByDoorAsync(Guid doorId, CancellationToken cancellationToken) =>
        WhereAsync(r => r.DoorIds.Contains(doorId));

    public Task<IReadOnlyList<AccessGroup>> ListByScheduleAsync(Guid scheduleId, CancellationToken cancellationToken) =>
        WhereAsync(r => r.ScheduleId == scheduleId);

    protected override AccessGroupRecord ToRecord(AccessGroup g) =>
        new(g.Id, g.Name, g.ScheduleId, g.DoorIds.Order().ToList());

    protected override AccessGroup ToAggregate(AccessGroupRecord r) =>
        AccessGroup.Rehydrate(r.Id, r.Name, r.ScheduleId, r.DoorIds ?? []);
}
