namespace AccessControl.Infrastructure.Storage;

/// <summary>
/// The newest entry deleted by retention, kept in <c>&lt;name&gt;.anchor.json</c>. Verification accepts a chain that does
/// not start at entry 1 only if it continues from this anchor, so removing the oldest files by any other means is
/// detected. <see cref="Signature"/> is keyed like the chain itself (<see cref="AuditChainHasher.SignAnchor"/>).
/// </summary>
internal sealed record AuditChainAnchor(long Sequence, string Hash, string Signature);
