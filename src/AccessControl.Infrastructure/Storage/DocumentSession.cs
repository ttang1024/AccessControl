using System.Runtime.CompilerServices;
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
/// revocation with a cardholder loaded after it). A document read once is read the same way again (repeatable
/// read), and after a commit the session tracks the versions it wrote, so it can keep working.
/// </para>
/// </summary>
internal sealed class DocumentSession(DocumentStore store, IActorContext actor) : IUnitOfWork
{
    // Stored documents are immutable, so the record deserialised from one can be shared by every request that reads
    // it until a commit replaces it. Records are immutable too (Records.cs); aggregates are built fresh from them.
    private static readonly ConditionalWeakTable<StoredDocument, object> Materialised = [];

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

        if (_loaded.TryGetValue((collection, id), out var loaded))
        {
            return Materialise<TRecord>(loaded);
        }

        var doc = View.Get(collection, id);
        if (doc is null)
        {
            return null;
        }

        _loaded[(collection, id)] = doc;
        return Materialise<TRecord>(doc);
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

    /// <summary>The version of a document as loaded, or as last committed, in this unit of work.</summary>
    public int VersionOf(string collection, Guid id) =>
        _loaded.TryGetValue((collection, id), out var doc)
            ? doc.Version
            : throw new InvalidOperationException(
                $"Document {collection}/{id} has no known version in this unit of work: it was neither loaded nor committed here.");

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
        var committed = await store.CommitAsync(_pending.Values.ToList(), actor.Actor, cancellationToken).ConfigureAwait(false);
        _pending.Clear();

        // Track what this commit wrote at its new versions, so the session can report them and write again.
        foreach (var (collection, id, doc) in committed)
        {
            if (doc is null)
            {
                _loaded.Remove((collection, id));
            }
            else
            {
                _loaded[(collection, id)] = doc;
            }
        }

        _view = null;
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

    private static TRecord Materialise<TRecord>(StoredDocument doc)
        where TRecord : class =>
        Materialised.GetValue(doc, d => Deserialize<TRecord>(d.Body)) as TRecord ?? Deserialize<TRecord>(doc.Body);

    private static JsonElement Serialize<TRecord>(TRecord record) =>
        JsonSerializer.SerializeToElement(record, StorageJson.Options);

    private static TRecord Deserialize<TRecord>(JsonElement body) =>
        body.Deserialize<TRecord>(StorageJson.Options)
        ?? throw new InvalidDataException($"Stored {typeof(TRecord).Name} deserialized to null.");
}
