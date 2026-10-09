using System.Text.Json;
using AccessControl.Application.Abstractions;

namespace AccessControl.Infrastructure.Storage;

/// <summary>
/// Per-request unit of work over <see cref="DocumentStore"/>. Remembers the version of every
/// document it hands out so that a later write can be checked for lost updates, and stages
/// writes until <see cref="CommitAsync"/>. Reads see the session's own staged writes.
/// <para>
/// All reads in a unit of work come from one committed snapshot, taken at the first read, so a request
/// never combines data from before and after a concurrent commit (e.g. a credential loaded before a
/// revocation with a cardholder loaded after it). The snapshot is refreshed after this session commits.
/// </para>
/// </summary>
internal sealed class DocumentSession(DocumentStore store, IActorContext actor) : IUnitOfWork
{
    private readonly Dictionary<(string Collection, Guid Id), StoredDocument> _loaded = [];
    private readonly Dictionary<(string Collection, Guid Id), PendingChange> _pending = [];
    private StoreSnapshot? _view;

    private StoreSnapshot View => _view ??= store.Current;

    public TRecord? Load<TRecord>(string collection, Guid id)
        where TRecord : class
    {
        if (_pending.TryGetValue((collection, id), out var staged))
        {
            return staged.Body is { } body ? Deserialize<TRecord>(body) : null;
        }

        return Track<TRecord>(collection, View.Get(collection, id));
    }

    public TRecord? LoadByKey<TRecord>(string collection, string indexName, string key)
        where TRecord : class =>
        View.FindId(indexName, key) is { } id ? Load<TRecord>(collection, id) : null;

    /// <summary>Every document in the collection, including this session's staged changes.</summary>
    public IEnumerable<TRecord> Query<TRecord>(string collection)
        where TRecord : class
    {
        var committedIds = new HashSet<Guid>();
        foreach (var doc in View.All(collection))
        {
            committedIds.Add(doc.Id);
            if (Load<TRecord>(collection, doc.Id) is { } record)
            {
                yield return record;
            }
        }

        foreach (var change in _pending.Values.Where(c => c.Collection == collection && !committedIds.Contains(c.Id)))
        {
            if (change.Body is { } body)
            {
                yield return Deserialize<TRecord>(body);
            }
        }
    }

    public void Insert<TRecord>(string collection, Guid id, TRecord record) =>
        Stage(collection, id, ExpectedVersionForInsert(collection, id), Serialize(record));

    /// <summary>
    /// Stages an update, unless the record serialises exactly as it was loaded: a command that changed nothing then
    /// writes nothing and leaves no change-trail entry.
    /// </summary>
    public void Replace<TRecord>(string collection, Guid id, TRecord record)
    {
        var expectedVersion = ExpectedVersionForExisting(collection, id);
        var body = Serialize(record);
        if (!_pending.ContainsKey((collection, id))
            && _loaded.TryGetValue((collection, id), out var loaded)
            && loaded.Body.GetRawText() == body.GetRawText())
        {
            return;
        }

        Stage(collection, id, expectedVersion, body);
    }

    public void Delete(string collection, Guid id) =>
        Stage(collection, id, ExpectedVersionForExisting(collection, id), body: null);

    public async Task CommitAsync(CancellationToken cancellationToken)
    {
        await store.CommitAsync(_pending.Values.ToList(), actor.Actor, cancellationToken).ConfigureAwait(false);

        // Versions moved on; anything still held by the caller must be reloaded before another write.
        _pending.Clear();
        _loaded.Clear();
        _view = null;
    }

    private TRecord? Track<TRecord>(string collection, StoredDocument? doc)
        where TRecord : class
    {
        if (doc is null)
        {
            return null;
        }

        _loaded.TryAdd((collection, doc.Id), doc);
        return Deserialize<TRecord>(doc.Body);
    }

    private int ExpectedVersionForInsert(string collection, Guid id) =>
        _pending.TryGetValue((collection, id), out var staged) ? staged.ExpectedVersion : 0;

    private int ExpectedVersionForExisting(string collection, Guid id)
    {
        if (_pending.TryGetValue((collection, id), out var staged))
        {
            return staged.ExpectedVersion;
        }

        return _loaded.TryGetValue((collection, id), out var loaded)
            ? loaded.Version
            : throw new InvalidOperationException(
                $"Document {collection}/{id} must be loaded in this unit of work before it is updated or removed.");
    }

    private void Stage(string collection, Guid id, int expectedVersion, JsonElement? body) =>
        _pending[(collection, id)] = new PendingChange(collection, id, expectedVersion, body);

    private static JsonElement Serialize<TRecord>(TRecord record) =>
        JsonSerializer.SerializeToElement(record, StorageJson.Options);

    private static TRecord Deserialize<TRecord>(JsonElement body) =>
        body.Deserialize<TRecord>(StorageJson.Options)
        ?? throw new InvalidDataException($"Stored {typeof(TRecord).Name} deserialized to null.");
}
