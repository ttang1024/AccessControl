using AccessControl.Domain.Common;

namespace AccessControl.Application.Abstractions;

public readonly record struct PageRequest
{
    public const int DefaultLimit = 50;
    public const int MaxLimit = 500;

    public PageRequest(int offset, int limit)
    {
        if (offset < 0)
        {
            throw DomainException.Validation("offset.invalid", "offset must not be negative.");
        }

        if (limit is < 1 or > MaxLimit)
        {
            throw DomainException.Validation("limit.invalid", $"limit must be between 1 and {MaxLimit}.");
        }

        Offset = offset;
        Limit = limit;
    }

    public int Offset { get; }

    public int Limit { get; }

    public static PageRequest From(int? offset, int? limit) => new(offset ?? 0, limit ?? DefaultLimit);
}

public sealed record PagedResult<T>(IReadOnlyList<T> Items, int Total, int Offset, int Limit)
{
    public PagedResult<TOut> Map<TOut>(Func<T, TOut> map) =>
        new(Items.Select(map).ToList(), Total, Offset, Limit);
}

public static class PagedResult
{
    /// <summary>Pages an already-ordered sequence in memory.</summary>
    public static PagedResult<T> Create<T>(IEnumerable<T> orderedSource, PageRequest page)
    {
        var all = orderedSource as IReadOnlyCollection<T> ?? orderedSource.ToList();
        var items = all.Skip(page.Offset).Take(page.Limit).ToList();
        return new PagedResult<T>(items, all.Count, page.Offset, page.Limit);
    }
}
