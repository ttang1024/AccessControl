using System.Runtime.InteropServices;

namespace AccessControl.Infrastructure.Storage;

/// <summary>
/// Crash-safe file replacement and renames. A rename is atomic, but on Linux it only survives a power loss once the
/// parent directory has been flushed too, so every rename here is followed by an fsync of the directory.
/// </summary>
internal static partial class DurableFile
{
    /// <summary>Writes <paramref name="path"/> through a flushed temp file and an atomic, durable rename.</summary>
    public static void Replace(string path, Action<Stream> write)
    {
        var temp = path + ".tmp";
        using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            write(stream);
            stream.Flush(flushToDisk: true);
        }

        Move(temp, path, overwrite: true);
    }

    /// <summary>Renames a file and flushes the directory entry to disk.</summary>
    public static void Move(string source, string destination, bool overwrite = false)
    {
        File.Move(source, destination, overwrite);
        FlushDirectory(Path.GetDirectoryName(Path.GetFullPath(destination))!);
    }

    /// <summary>Flushes a directory's entries (creates, renames, deletes) to disk. A no-op on Windows (NTFS journals them).</summary>
    public static void FlushDirectory(string directory)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var fd = Native.Open(directory, flags: 0 /* O_RDONLY */);
        if (fd < 0)
        {
            throw new IOException($"Could not open directory '{directory}' to flush it (errno {Marshal.GetLastPInvokeError()}).");
        }

        try
        {
            if (Native.Fsync(fd) != 0)
            {
                throw new IOException($"Could not flush directory '{directory}' (errno {Marshal.GetLastPInvokeError()}).");
            }
        }
        finally
        {
            _ = Native.Close(fd);
        }
    }

    private static partial class Native
    {
        [LibraryImport("libc", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        public static partial int Open(string path, int flags);

        [LibraryImport("libc", EntryPoint = "fsync", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        public static partial int Fsync(int fd);

        [LibraryImport("libc", EntryPoint = "close", SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        public static partial int Close(int fd);
    }
}
