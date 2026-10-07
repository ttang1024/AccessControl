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
/// Commits are serialized, validated (versions, unique keys) against the latest snapshot,
/// recorded in the change audit log, written to disk atomically (temp file + rename), and only then published.
/// A commit that fails validation or auditing leaves memory, disk and the audit log unchanged.
/// </para>
/// </summary>
internal sealed partial class DocumentStore
{
    private const int FormatVersion = 1;
    private const string FileName = "store.json";

    private readonly object _commitGate = new();
    private readonly string _path;
    private readonly IReadOnlyList<UniqueIndex> _indexes;
    private readonly JsonLinesChangeLog _changeLog;
    private readonly TimeProvider _clock;
    private readonly ILogger<DocumentStore> _logger;
    private StoreSnapshot _snapshot;

    public DocumentStore(
        IOptions<StorageOptions> options,
        IEnumerable<UniqueIndex> indexes,
        JsonLinesChangeLog changeLog,
        TimeProvider clock,
        ILogger<DocumentStore> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        _logger = logger;
        _indexes = indexes.ToList();
        _changeLog = changeLog;
        _clock = clock;

        var directory = Path.GetFullPath(options.Value.DataDirectory);
        Directory.CreateDirectory(directory);
        _path = Path.Combine(directory, FileName);
        _snapshot = Load();
    }

    public string FilePath => _path;

    /// <summary>The latest committed state.</summary>
    public StoreSnapshot Current => Volatile.Read(ref _snapshot);

    public string CollectionOf(string indexName) =>
        _indexes.FirstOrDefault(i => i.Name == indexName)?.Collection
        ?? throw new InvalidOperationException($"Unknown index '{indexName}'.");

    /// <exception cref="ConflictException">Version mismatch or unique-key violation; nothing was written.</exception>
    public void Commit(IReadOnlyCollection<PendingChange> changes, string actor)
    {
        if (changes.Count == 0)
        {
            return;
        }

        lock (_commitGate)
        {
            var (next, applied) = Apply(_snapshot, changes);

            // Audit first: a change must never exist without its record. If persisting then fails, the trail
            // holds an entry for a change that did not happen, which is the safe direction to err in.
            _changeLog.Append(ToChangeRecords(applied, actor));
            Persist(next);
            Volatile.Write(ref _snapshot, next);
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

    private void Persist(StoreSnapshot snapshot)
    {
        var file = new StoreFile(
            FormatVersion,
            snapshot.Collections.ToDictionary(
                c => c.Key,
                c => c.Value.Values.OrderBy(d => d.Id).ToList()));

        var tempPath = _path + ".tmp";
        using (var stream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(stream, file, StorageJson.Options);
            stream.Flush(flushToDisk: true);
        }

        File.Move(tempPath, _path, overwrite: true);
    }

    private StoreSnapshot Load()
    {
        if (!File.Exists(_path))
        {
            Log.StoreCreated(_logger, _path);
            return StoreSnapshot.Empty;
        }

        StoreFile? file;
        using (var stream = File.OpenRead(_path))
        {
            file = JsonSerializer.Deserialize<StoreFile>(stream, StorageJson.Options);
        }

        if (file is null || file.FormatVersion != FormatVersion)
        {
            throw new InvalidDataException(
                $"'{_path}' has unsupported format version {file?.FormatVersion}; expected {FormatVersion}.");
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

        Log.StoreLoaded(_logger, _path, changes.Count);
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
