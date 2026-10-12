namespace AccessControl.Application.Abstractions;

/// <summary>
/// A resource representation at a known version. The API sends <see cref="Version"/> as the <c>ETag</c> and accepts it
/// back as <c>If-Match</c>, so a client editing from a stale copy gets 412 instead of overwriting someone else's change.
/// </summary>
public interface IVersioned
{
    int Version { get; }
}
