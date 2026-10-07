namespace AccessControl.Infrastructure.Storage;

public sealed class StorageOptions
{
    public const string SectionName = "Storage";

    /// <summary>
    /// Directory holding <c>store.json</c> and the audit logs (<c>access-events*.jsonl</c>,
    /// <c>changes*.jsonl</c>). Created if missing.
    /// </summary>
    public string DataDirectory { get; set; } = "data";

    /// <summary>
    /// When true (default), every audit append is flushed to the physical disk before the
    /// access decision is returned. Disable only on storage with its own write-back guarantees.
    /// </summary>
    public bool FlushAuditToDisk { get; set; } = true;

    /// <summary>
    /// Secret for the audit logs' hash chain. When set, each line carries an HMAC-SHA256 so that someone
    /// with write access to the data directory but not this key cannot rewrite history undetected.
    /// When empty, a plain SHA-256 chain is used, which only detects naive edits.
    /// Keep it in a secret store, not in appsettings; changing it makes earlier lines fail verification.
    /// </summary>
    public string? AuditHmacKey { get; set; }

    /// <summary>An audit log file is closed and a new one started once it reaches this size.</summary>
    public long AuditSegmentMaxBytes { get; set; } = 64L * 1024 * 1024;

    /// <summary>
    /// Closed audit segments older than this are deleted (checked at startup and on rotation).
    /// <c>null</c> (default) keeps everything: deleting audit history is a policy decision for the site.
    /// </summary>
    public int? AuditRetentionDays { get; set; }

    /// <summary>The health check reports unhealthy below this much free space on the data volume.</summary>
    public long MinimumFreeDiskBytes { get; set; } = 1024L * 1024 * 1024;
}
