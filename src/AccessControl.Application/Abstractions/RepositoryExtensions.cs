using AccessControl.Application.Errors;

namespace AccessControl.Application.Abstractions;

internal static class RepositoryExtensions
{
    public static async Task<T> GetRequiredAsync<T>(
        this IRepository<T> repository, Guid id, string resourceName, CancellationToken cancellationToken)
        where T : class =>
        await repository.GetAsync(id, cancellationToken).ConfigureAwait(false)
        ?? throw new NotFoundException(resourceName, id);
}
