using AccessControl.Application.Errors;

namespace AccessControl.Application.Abstractions;

internal static class RepositoryExtensions
{
    public static async Task<T> GetRequiredAsync<T>(
        this IRepository<T> repository, Guid id, string resourceName, CancellationToken cancellationToken)
        where T : class =>
        await repository.GetAsync(id, cancellationToken).ConfigureAwait(false)
        ?? throw new NotFoundException(resourceName, id);

    /// <summary>
    /// Loads an aggregate the caller intends to change. With <paramref name="expectedVersion"/> (the client's
    /// <c>If-Match</c>) it must still be at that version: the client decided on the change from that copy.
    /// </summary>
    public static async Task<T> GetForChangeAsync<T>(
        this IRepository<T> repository, Guid id, string resourceName, int? expectedVersion, CancellationToken cancellationToken)
        where T : class
    {
        var aggregate = await repository.GetRequiredAsync(id, resourceName, cancellationToken).ConfigureAwait(false);
        if (expectedVersion is { } expected && repository.VersionOf(aggregate) is var actual && actual != expected)
        {
            throw new PreconditionFailedException(resourceName, id, expected, actual);
        }

        return aggregate;
    }

    /// <summary>
    /// One command on one aggregate: load it (404 if missing, 412 if not at <paramref name="expectedVersion"/>),
    /// apply <paramref name="change"/>, stage and commit. A change that leaves the aggregate as it was writes nothing
    /// (see <see cref="IRepository{T}.Update"/>). References the change adds are checked by the store at commit.
    /// </summary>
    public static async Task<T> ModifyAsync<T>(
        this IRepository<T> repository,
        IUnitOfWork unitOfWork,
        Guid id,
        string resourceName,
        int? expectedVersion,
        Action<T> change,
        CancellationToken cancellationToken)
        where T : class
    {
        var aggregate = await repository.GetForChangeAsync(id, resourceName, expectedVersion, cancellationToken).ConfigureAwait(false);
        change(aggregate);
        repository.Update(aggregate);
        await unitOfWork.CommitAsync(cancellationToken).ConfigureAwait(false);
        return aggregate;
    }
}
