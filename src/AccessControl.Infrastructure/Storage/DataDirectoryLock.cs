using Microsoft.Extensions.Options;

namespace AccessControl.Infrastructure.Storage;

/// <summary>
/// Exclusive ownership of the data directory for the life of the process. Two processes over one directory (e.g. a
/// rolling deployment that starts the new instance before stopping the old one) would overwrite each other's store
/// and fork the audit chains, so the second one fails at startup instead. The lock is an OS file lock (released
/// automatically if the process dies); it is advisory and may not hold on network file systems.
/// </summary>
internal sealed class DataDirectoryLock : IDisposable
{
    public const string FileName = ".lock";

    private readonly FileStream _handle;

    public DataDirectoryLock(IOptions<StorageOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        DirectoryPath = Path.GetFullPath(options.Value.DataDirectory);
        Directory.CreateDirectory(DirectoryPath);
        var path = Path.Combine(DirectoryPath, FileName);
        try
        {
            _handle = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException ex)
        {
            throw new InvalidOperationException(
                $"Data directory '{DirectoryPath}' is in use by another process. Only one instance may use a data directory: " +
                "stop the other one first (deploy with a stop-then-start strategy, not a rolling update).",
                ex);
        }
    }

    public string DirectoryPath { get; }

    public void Dispose() => _handle.Dispose();
}
