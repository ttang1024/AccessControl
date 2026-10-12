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

/// <summary>A document as a commit left it; <see cref="Document"/> is <c>null</c> if the commit deleted it.</summary>
internal sealed record CommittedDocument(string Collection, Guid Id, StoredDocument? Document);

/// <summary>
/// A uniqueness constraint on one (serialised) property of one collection, also used as a lookup index.
/// Name the property with <see cref="StorageJson.PropertyName"/> and <c>nameof</c>, so a rename cannot switch it off.
/// </summary>
internal sealed record UniqueIndex(
    string Collection,
    string Name,
    string Property,
    Func<string, Exception> Violation)
{
    public string? KeyOf(JsonElement body) =>
        body.TryGetProperty(Property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}

/// <summary>
/// A reference from documents in <see cref="Collection"/> (property <see cref="Property"/>, a Guid or a Guid array)
/// to documents in <see cref="Target"/>, enforced at commit like a database foreign key: a commit may not add a
/// reference to a missing target, nor delete a target that is still referenced. This is the only place the rule is
/// checked, so it is also where the client-facing errors come from. Name the property like <see cref="UniqueIndex"/>.
/// </summary>
internal sealed record ForeignKey(
    string Collection,
    string Target,
    string Property,
    Func<Guid, Exception> MissingTarget,
    Func<IReadOnlyList<JsonElement>, Exception> TargetInUse)
{
    public IEnumerable<Guid> TargetsOf(JsonElement body)
    {
        if (!body.TryGetProperty(Property, out var value))
        {
            yield break;
        }

        if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in value.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String && item.TryGetGuid(out var id))
                {
                    yield return id;
                }
            }
        }
        else if (value.ValueKind == JsonValueKind.String && value.TryGetGuid(out var id))
        {
            yield return id;
        }
    }
}

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
/// Single-node document store with optimistic concurrency, unique indexes and foreign keys.
/// <para>
/// State is an immutable snapshot: reads are lock-free and always see a committed state. Commits are serialized and
/// validated (versions, unique keys, references) against the latest snapshot.
/// </para>
/// <para>
/// <b>The change log is the write-ahead log.</b> A commit is durable, and has happened, once its entries are in the
/// change log (one fsync'd append that carries the full new documents); only then is it published in memory. The
/// whole store is written to <c>store.json</c> only as a checkpoint, every <see cref="StorageOptions.CheckpointEveryCommits"/>
/// commits and at shutdown, and startup replays the change log after the checkpoint. So a change and its audit entry
/// can never disagree, and a commit costs one append instead of a rewrite of every document.
/// </para>
/// </summary>
internal sealed partial class DocumentStore : IDisposable
{
    /// <summary>2: a checkpoint of the change log (format 1, rewritten on every commit, is no longer read).</summary>
    private const int FormatVersion = 2;
    private const string FileName = "store.json";

    // Async so that requests waiting to commit do not block thread-pool threads during another commit's disk I/O.
    private readonly SemaphoreSlim _commitGate = new(1, 1);
    private readonly IReadOnlyList<UniqueIndex> _indexes;
    private readonly IReadOnlyList<ForeignKey> _foreignKeys;
    private readonly JsonLinesChangeLog _changeLog;
    private readonly TimeProvider _clock;
    private readonly ILogger<DocumentStore> _logger;
    private readonly int _checkpointEvery;
    private StoreSnapshot _snapshot;
    private int _commitsSinceCheckpoint;

    public DocumentStore(
        IOptions<StorageOptions> options,
        DataDirectoryLock directory,
        IEnumerable<UniqueIndex> indexes,
        IEnumerable<ForeignKey> foreignKeys,
        JsonLinesChangeLog changeLog,
        TimeProvider clock,
        ILogger<DocumentStore> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(directory);
        _logger = logger;
        _indexes = indexes.ToList();
        _foreignKeys = foreignKeys.ToList();
        _changeLog = changeLog;
        _clock = clock;
        _checkpointEvery = Math.Max(1, options.Value.CheckpointEveryCommits);

        FilePath = Path.Combine(directory.DirectoryPath, FileName);
        _snapshot = Load();
    }

    public string FilePath { get; }

    /// <summary>The latest committed state.</summary>
    public StoreSnapshot Current => Volatile.Read(ref _snapshot);

    /// <summary>Validates and durably records <paramref name="changes"/>, then publishes them.</summary>
    /// <returns>Every changed document as committed (new version), for the caller to keep tracking.</returns>
    /// <exception cref="ConflictException">Version mismatch, unique-key violation or a deleted target still in use; nothing was written.</exception>
    /// <exception cref="NotFoundException">The commit adds a reference to a document that does not exist; nothing was written.</exception>
    public async Task<IReadOnlyList<CommittedDocument>> CommitAsync(
        IReadOnlyCollection<PendingChange> changes, string actor, CancellationToken cancellationToken)
    {
        if (changes.Count == 0)
        {
            return [];
        }

        await _commitGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var (next, applied) = Apply(_snapshot, changes);
            CheckReferences(next, applied);

            // The commit point. Not cancellable from here on: the log and memory must not diverge because a client
            // went away. If the append fails nothing was recorded (a failed append is cut off the log) or published.
            await _changeLog.AppendAsync(ToChangeRecords(applied, actor)).ConfigureAwait(false);
            Volatile.Write(ref _snapshot, next);

            if (++_commitsSinceCheckpoint >= _checkpointEvery)
            {
                TryCheckpoint(next);
            }

            return applied.Select(a => new CommittedDocument(a.Collection, a.Id, a.Updated)).ToList();
        }
        finally
        {
            _commitGate.Release();
        }
    }

    /// <summary>Writes a final checkpoint so the next start has nothing to replay.</summary>
    public void Dispose()
    {
        if (_commitsSinceCheckpoint > 0)
        {
            TryCheckpoint(Current);
        }

        _commitGate.Dispose();
    }

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
                    foreach (var target in key.TargetsOf(updated.Body))
                    {
                        if (next.Get(key.Target, target) is null)
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
                a.Updated?.Body,
                applied.Count))
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

    private void TryCheckpoint(StoreSnapshot snapshot)
    {
        // The commit is already durable in the change log; a failed checkpoint only means a longer replay at startup.
        try
        {
            Checkpoint(snapshot);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Log.CheckpointFailed(_logger, ex, FilePath);
        }
    }

    private void Checkpoint(StoreSnapshot snapshot)
    {
        var file = ToFile(snapshot);
        DurableFile.Replace(FilePath, s => JsonSerializer.Serialize(s, file, StorageJson.Options));
        _commitsSinceCheckpoint = 0;
    }

    /// <summary>Every commit up to the change log's head is in <paramref name="snapshot"/> (callers hold the gate or are starting).</summary>
    private StoreFile ToFile(StoreSnapshot snapshot)
    {
        var head = _changeLog.Log.Head;
        return new StoreFile(
            FormatVersion,
            head.Sequence,
            head.Hash,
            snapshot.Collections.ToDictionary(c => c.Key, c => c.Value.Values.OrderBy(d => d.Id).ToList()));
    }

    private StoreSnapshot Load()
    {
        StoreFile? file = null;
        if (File.Exists(FilePath))
        {
            using var stream = File.OpenRead(FilePath);
            file = JsonSerializer.Deserialize<StoreFile>(stream, StorageJson.Options)
                ?? throw new InvalidDataException($"'{FilePath}' is empty.");
        }

        var docs = (file?.Collections ?? []).ToDictionary(c => c.Key, c => c.Value.ToDictionary(d => d.Id));

        // Where the checkpoint stands in the change log. No store at all: the log holds every commit since the beginning.
        var (sequence, hash) = file switch
        {
            null => (0L, AuditChainHasher.EmptyHash),
            { FormatVersion: FormatVersion } f => (f.ChangeSequence, f.ChangeHash),
            _ => throw new InvalidDataException(
                $"'{FilePath}' has unsupported format version {file.FormatVersion}; expected {FormatVersion}. " +
                "Data from versions before the change log became the write-ahead log is not migrated: start with an empty data directory."),
        };

        var replayed = Replay(docs, sequence, hash);

        // Rebuild through Apply so unique indexes are reconstructed and validated on startup.
        var all = docs.SelectMany(c => c.Value.Values.Select(d => (Collection: c.Key, Doc: d))).ToList();
        var (rebuilt, _) = Apply(StoreSnapshot.Empty, all.Select(x => new PendingChange(x.Collection, x.Doc.Id, 0, x.Doc.Body)).ToList());

        // Apply assigned version 1 to everything; restore the real versions.
        var snapshot = rebuilt with
        {
            Collections = docs.ToImmutableDictionary(c => c.Key, c => c.Value.ToImmutableDictionary()),
        };

        if (replayed > 0)
        {
            Checkpoint(snapshot);
        }

        Log.StoreLoaded(_logger, FilePath, all.Count, replayed);
        return snapshot;
    }

    /// <summary>
    /// Re-applies the commits recorded in the change log after the checkpoint. Each must apply exactly (a create of
    /// a missing document, an update or delete of the version it followed); anything else means the checkpoint and
    /// the log disagree, and starting would serve configuration nobody can account for. A commit whose entries are
    /// not all present (cut off by a crash before it was acknowledged) is skipped.
    /// </summary>
    private int Replay(Dictionary<string, Dictionary<Guid, StoredDocument>> docs, long sequence, string hash)
    {
        var records = _changeLog.ReadAfter(sequence, hash).ToList();
        var commits = 0;
        foreach (var commit in Consecutive(records, r => r.Record.CommitId))
        {
            if (commit.Count != commit[0].Record.CommitSize)
            {
                Log.IncompleteCommitSkipped(_logger, commit[0].Record.CommitId, commit.Count, commit[0].Record.CommitSize);
                continue;
            }

            foreach (var (seq, r) in commit)
            {
                var collection = docs.TryGetValue(r.Collection, out var c) ? c : docs[r.Collection] = [];
                collection.TryGetValue(r.EntityId, out var current);
                var consistent = r.Kind switch
                {
                    ChangeKind.Created => current is null && r.Version == 1,
                    ChangeKind.Updated => current is not null && current.Version == r.Version - 1,
                    _ => current is not null && current.Version == r.Version,
                };

                if (!consistent || (r.Kind != ChangeKind.Deleted && r.After is null))
                {
                    throw new InvalidDataException(
                        $"Change log entry {seq} ({r.Kind} {r.Collection}/{r.EntityId} v{r.Version}) does not apply to '{FilePath}'; " +
                        "the checkpoint and the change log disagree.");
                }

                if (r.Kind == ChangeKind.Deleted)
                {
                    collection.Remove(r.EntityId);
                }
                else
                {
                    collection[r.EntityId] = new StoredDocument(r.EntityId, r.Version, r.After!.Value);
                }
            }

            commits++;
        }

        return commits;
    }

    private static IEnumerable<List<T>> Consecutive<T, TKey>(IEnumerable<T> items, Func<T, TKey> key)
    {
        List<T>? group = null;
        foreach (var item in items)
        {
            if (group is not null && !EqualityComparer<TKey>.Default.Equals(key(group[0]), key(item)))
            {
                yield return group;
                group = null;
            }

            (group ??= []).Add(item);
        }

        if (group is not null)
        {
            yield return group;
        }
    }

    private sealed record AppliedChange(string Collection, Guid Id, StoredDocument? Previous, StoredDocument? Updated);

    /// <param name="ChangeSequence">The change-log entry this checkpoint includes everything up to.</param>
    /// <param name="ChangeHash">That entry's hash, so replay can check the log continues from it.</param>
    private sealed record StoreFile(
        int FormatVersion,
        long ChangeSequence,
        string ChangeHash,
        Dictionary<string, List<StoredDocument>> Collections);

    private static partial class Log
    {
        [LoggerMessage(EventId = 3001, Level = LogLevel.Information, Message = "Loaded {Count} documents from {Path} ({Replayed} commits replayed from the change log)")]
        public static partial void StoreLoaded(ILogger logger, string path, int count, int replayed);

        [LoggerMessage(EventId = 3002, Level = LogLevel.Warning, Message = "Could not write the store checkpoint {Path}; commits stay durable in the change log and will be replayed at startup")]
        public static partial void CheckpointFailed(ILogger logger, Exception exception, string path);

        [LoggerMessage(EventId = 3003, Level = LogLevel.Warning, Message = "Skipped commit {CommitId} during replay: {Count} of its {Size} change-log entries are present (cut off by a crash before it completed)")]
        public static partial void IncompleteCommitSkipped(ILogger logger, Guid commitId, int count, int size);
    }
}
