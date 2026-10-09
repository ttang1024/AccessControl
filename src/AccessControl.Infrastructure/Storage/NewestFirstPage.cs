using AccessControl.Application.Abstractions;

namespace AccessControl.Infrastructure.Storage;

/// <summary>
/// Collects one page of a log scan, newest first, while holding only <c>offset + limit</c> entries in memory.
/// Entries are ranked by timestamp, then by position in the log, so equal timestamps stay newest-appended first
/// and clock adjustments cannot reorder results.
/// </summary>
internal sealed class NewestFirstPage<T>(PageRequest page)
{
    private readonly int _capacity = page.Offset + page.Limit;

    // Min-heap of the best entries seen so far: the root is the first one to drop when a newer one arrives.
    private readonly PriorityQueue<T, (DateTimeOffset OccurredAt, long Position)> _kept = new();

    private int _total;

    /// <param name="position">Position in the log, increasing in append order.</param>
    public void Add(T item, DateTimeOffset occurredAt, long position)
    {
        _total++;
        if (_kept.Count < _capacity)
        {
            _kept.Enqueue(item, (occurredAt, position));
        }
        else
        {
            _kept.EnqueueDequeue(item, (occurredAt, position));
        }
    }

    public PagedResult<T> ToResult()
    {
        var items = _kept.UnorderedItems
            .OrderByDescending(x => x.Priority)
            .Skip(page.Offset)
            .Select(x => x.Element)
            .ToList();
        return new PagedResult<T>(items, _total, page.Offset, page.Limit);
    }
}
