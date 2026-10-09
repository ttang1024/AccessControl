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
    /// One command on one aggregate: load it (404 if missing), apply <paramref name="change"/>, stage and commit.
    /// A change that leaves the aggregate as it was writes nothing (see <see cref="IRepository{T}.Update"/>).
    /// </summary>
    public static async Task<T> ModifyAsync<T>(
        this IRepository<T> repository,
        IUnitOfWork unitOfWork,
        Guid id,
        string resourceName,
        Action<T> change,
        CancellationToken cancellationToken)
        where T : class
    {
        var aggregate = await repository.GetRequiredAsync(id, resourceName, cancellationToken).ConfigureAwait(false);
        change(aggregate);
        repository.Update(aggregate);
        await unitOfWork.CommitAsync(cancellationToken).ConfigureAwait(false);
        return aggregate;
    }
}
