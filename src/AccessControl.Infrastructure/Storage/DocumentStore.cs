using System.Collections.Immutable;
using System.Text.Json;
using AccessControl.Application.Abstractions;
using AccessControl.Application.Errors;
using AccessControl.Infrastructure.Persistence;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AccessControl.Infrastructure.Storage;

internal sealed record StoredDocument(Guid Id, int Version, JsonElement Body);

/// <summary>A staged write. <see cref="Body"/> is <c>null</c> for a delete.</summary>
internal sealed record PendingChange(string Collection, Guid Id, int ExpectedVersion, JsonElement? Body);

/// <summary>A uniqueness constraint over one collection, also used as a lookup index.</summary>
internal sealed record UniqueIndex(
    string Collection,
    string Name,
    Func<JsonElement, string?> KeyOf,
    Func<string, Exception> Violation);

/// <summary>
/// A reference from documents in <see cref="Collection"/> to documents in <see cref="Target"/>, enforced at commit
/// like a database foreign key: a commit may not add a reference to a missing target, nor delete a target that is
/// still referenced. Services check the same rules first for a clear error; this closes the race between them.
/// References that already dangle (written before this check existed) do not block unrelated updates.
/// </summary>
internal sealed record ForeignKey(
    string Collection,
    string Target,
    Func<JsonElement, IEnumerable<Guid>> TargetsOf,
    Func<Guid, Exception> MissingTarget,
    Func<IReadOnlyList<JsonElement>, Exception> TargetInUse);

/// <summary>An immutable, committed state of the whole store. Safe to read from any thread.</summary>
internal sealed record StoreSnapshot(
    ImmutableDictionary<string, ImmutableDictionary<Guid, StoredDocument>> Collections,
    ImmutableDictionary<string, ImmutableDictionary<string, Guid>> Indexes)
{
    public static readonly StoreSnapshot Empty = new(
        ImmutableDictionary<string, ImmutableDictionary<Guid, StoredDocument>>.Empty,
        ImmutableDictionary<string, ImmutableDictionary<string, Guid>>.Empty);

    public StoredDocument? Get(string collection, Guid id) =>
        Collections.TryGetValue(collection, out var docs) && docs.TryGetValue(id, out var doc) ? doc : null;

    public IEnumerable<StoredDocument> All(string collection) =>
        Collections.TryGetValue(collection, out var docs) ? docs.Values : [];

    public Guid? FindId(string indexName, string key) =>
        Indexes.TryGetValue(indexName, out var entries) && entries.TryGetValue(key, out var id) ? id : null;
}

/// <summary>
/// Single-node document store with optimistic concurrency and unique indexes.
/// <para>
/// State is an immutable snapshot: reads are lock-free and always see a committed state.
/// Commits are serialized, validated (versions, unique keys, references) against the latest snapshot,
/// recorded in the change audit log, written to disk atomically (temp file + rename), and only then published.
/// A commit that fails validation or auditing leaves memory, disk and the audit log unchanged.
/// </para>
/// </summary>
internal sealed partial class DocumentStore : IDisposable
{
    private const int FormatVersion = 1;
    private const string FileName = "store.json";

    // Async so that requests waiting to commit do not block thread-pool threads during another commit's disk I/O.
    private readonly SemaphoreSlim _commitGate = new(1, 1);
    private readonly IReadOnlyList<UniqueIndex> _indexes;
    private readonly IReadOnlyList<ForeignKey> _foreignKeys;
    private readonly JsonLinesChangeLog _changeLog;
    private readonly TimeProvider _clock;
    private readonly ILogger<DocumentStore> _logger;
    private StoreSnapshot _snapshot;

    public DocumentStore(
        IOptions<StorageOptions> options,
        IEnumerable<UniqueIndex> indexes,
        IEnumerable<ForeignKey> foreignKeys,
        JsonLinesChangeLog changeLog,
        TimeProvider clock,
        ILogger<DocumentStore> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        _logger = logger;
        _indexes = indexes.ToList();
        _foreignKeys = foreignKeys.ToList();
        _changeLog = changeLog;
        _clock = clock;

        var directory = Path.GetFullPath(options.Value.DataDirectory);
        Directory.CreateDirectory(directory);
        FilePath = Path.Combine(directory, FileName);
        _snapshot = Load();
    }

    public string FilePath { get; }

    /// <summary>The latest committed state.</summary>
    public StoreSnapshot Current => Volatile.Read(ref _snapshot);

    /// <exception cref="ConflictException">Version mismatch, unique-key violation or a deleted target still in use; nothing was written.</exception>
    /// <exception cref="NotFoundException">The commit adds a reference to a document that does not exist; nothing was written.</exception>
    public async Task CommitAsync(IReadOnlyCollection<PendingChange> changes, string actor, CancellationToken cancellationToken)
    {
        if (changes.Count == 0)
        {
            return;
        }

        await _commitGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var (next, applied) = Apply(_snapshot, changes);
            CheckReferences(next, applied);

            // Audit first: a change must never exist without its record. If persisting then fails, the trail
            // holds an entry for a change that did not happen, which is the safe direction to err in.
            // Not cancellable from here on: the trail and the store must not diverge because a client went away.
            await _changeLog.AppendAsync(ToChangeRecords(applied, actor)).ConfigureAwait(false);
            await PersistAsync(next).ConfigureAwait(false);
            Volatile.Write(ref _snapshot, next);
        }
        finally
        {
            _commitGate.Release();
        }
    }

    public void Dispose() => _commitGate.Dispose();

    /// <summary>
    /// Enforces <see cref="ForeignKey"/>s on the state after the commit: added references must point at existing
    /// documents, and deleted documents must not be referenced. Commits are serialized, so this cannot race.
    /// </summary>
    private void CheckReferences(StoreSnapshot next, List<AppliedChange> applied)
    {
        foreach (var change in applied)
        {
            foreach (var key in _foreignKeys)
            {
                if (key.Collection == change.Collection && change.Updated is { } updated)
                {
                    var existing = change.Previous is { } previous ? key.TargetsOf(previous.Body).ToHashSet() : [];
                    foreach (var target in key.TargetsOf(updated.Body))
                    {
                        if (!existing.Contains(target) && next.Get(key.Target, target) is null)
                        {
                            throw key.MissingTarget(target);
                        }
                    }
                }

                if (key.Target == change.Collection && change.Updated is null)
                {
                    var referrers = next.All(key.Collection)
                        .Where(d => key.TargetsOf(d.Body).Contains(change.Id))
                        .Select(d => d.Body)
                        .ToList();
                    if (referrers.Count > 0)
                    {
                        throw key.TargetInUse(referrers);
                    }
                }
            }
        }
    }

    private List<ChangeRecord> ToChangeRecords(List<AppliedChange> applied, string actor)
    {
        var commitId = Guid.NewGuid();
        var now = _clock.GetUtcNow();
        return applied
            .Select(a => new ChangeRecord(
                Guid.NewGuid(),
                now,
                actor,
                commitId,
                a.Collection,
                a.Id,
                (a.Previous, a.Updated) switch
                {
                    (null, _) => ChangeKind.Created,
                    (_, null) => ChangeKind.Deleted,
                    _ => ChangeKind.Updated,
                },
                a.Updated?.Version ?? a.Previous!.Version,
                a.Previous?.Body,
                a.Updated?.Body))
            .ToList();
    }

    private (StoreSnapshot Next, List<AppliedChange> Applied) Apply(StoreSnapshot current, IReadOnlyCollection<PendingChange> changes)
    {
        var collections = current.Collections.ToBuilder();
        var indexes = current.Indexes.ToBuilder();
        var applied = new List<AppliedChange>(changes.Count);

        foreach (var change in changes)
        {
            var docs = collections.TryGetValue(change.Collection, out var existing)
                ? existing
                : ImmutableDictionary<Guid, StoredDocument>.Empty;

            docs.TryGetValue(change.Id, out var previous);
            if ((previous?.Version ?? 0) != change.ExpectedVersion)
            {
                throw ConflictException.Concurrency();
            }

            StoredDocument? updated = change.Body is { } body
                ? new StoredDocument(change.Id, change.ExpectedVersion + 1, body)
                : null;

            foreach (var index in _indexes.Where(i => i.Collection == change.Collection))
            {
                var entries = indexes.TryGetValue(index.Name, out var e) ? e : ImmutableDictionary<string, Guid>.Empty;
                if (previous is not null && index.KeyOf(previous.Body) is { } oldKey)
                {
                    entries = entries.Remove(oldKey);
                }

                if (updated is not null && index.KeyOf(updated.Body) is { } newKey)
                {
                    if (entries.TryGetValue(newKey, out var owner) && owner != change.Id)
                    {
                        throw index.Violation(newKey);
                    }

                    entries = entries.SetItem(newKey, change.Id);
                }

                indexes[index.Name] = entries;
            }

            collections[change.Collection] = updated is null ? docs.Remove(change.Id) : docs.SetItem(change.Id, updated);
            applied.Add(new AppliedChange(change.Collection, change.Id, previous, updated));
        }

        return (new StoreSnapshot(collections.ToImmutable(), indexes.ToImmutable()), applied);
    }

    private async Task PersistAsync(StoreSnapshot snapshot)
    {
        var file = new StoreFile(
            FormatVersion,
            snapshot.Collections.ToDictionary(
                c => c.Key,
                c => c.Value.Values.OrderBy(d => d.Id).ToList()));

        var tempPath = FilePath + ".tmp";
        var stream = new FileStream(
            tempPath, FileMode.Create, FileAccess.Write, FileShare.None, bufferSize: 64 * 1024, useAsync: true);
        await using (stream.ConfigureAwait(false))
        {
            await JsonSerializer.SerializeAsync(stream, file, StorageJson.Options).ConfigureAwait(false);
            await stream.FlushAsync().ConfigureAwait(false);
            stream.Flush(flushToDisk: true);
        }

        File.Move(tempPath, FilePath, overwrite: true);
    }

    private StoreSnapshot Load()
    {
        if (!File.Exists(FilePath))
        {
            Log.StoreCreated(_logger, FilePath);
            return StoreSnapshot.Empty;
        }

        StoreFile? file;
        using (var stream = File.OpenRead(FilePath))
        {
            file = JsonSerializer.Deserialize<StoreFile>(stream, StorageJson.Options);
        }

        if (file is null || file.FormatVersion != FormatVersion)
        {
            throw new InvalidDataException(
                $"'{FilePath}' has unsupported format version {file?.FormatVersion}; expected {FormatVersion}.");
        }

        // Rebuild through Apply so unique indexes are reconstructed and validated on startup.
        var changes = file.Collections
            .SelectMany(c => c.Value.Select(d => (Collection: c.Key, Doc: d)))
            .Select(x => new PendingChange(x.Collection, x.Doc.Id, 0, x.Doc.Body))
            .ToList();
        var (rebuilt, _) = Apply(StoreSnapshot.Empty, changes);

        // Apply assigned version 1 to everything; restore the persisted versions.
        var collections = file.Collections.ToImmutableDictionary(
            c => c.Key,
            c => c.Value.ToImmutableDictionary(d => d.Id, d => d));

        Log.StoreLoaded(_logger, FilePath, changes.Count);
        return rebuilt with { Collections = collections };
    }

    private sealed record AppliedChange(string Collection, Guid Id, StoredDocument? Previous, StoredDocument? Updated);

    private sealed record StoreFile(int FormatVersion, Dictionary<string, List<StoredDocument>> Collections);

    private static partial class Log
    {
        [LoggerMessage(EventId = 3000, Level = LogLevel.Information, Message = "No store at {Path}; starting empty")]
        public static partial void StoreCreated(ILogger logger, string path);

        [LoggerMessage(EventId = 3001, Level = LogLevel.Information, Message = "Loaded {Count} documents from {Path}")]
        public static partial void StoreLoaded(ILogger logger, string path, int count);
    }
}
