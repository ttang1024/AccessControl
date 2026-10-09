using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace AccessControl.Infrastructure.Storage;

/// <summary>
/// Computes the audit chain link <c>h(n) = H(n + "\n" + h(n-1) + "\n" + data)</c>, where <c>H</c> is
/// HMAC-SHA256 when a key is configured and SHA-256 otherwise.
/// </summary>
internal sealed class AuditChainHasher(string? hmacKey)
{
    /// <summary>The <c>prev</c> of the first entry in a chain.</summary>
    public const string EmptyHash = "";

    // Entry payloads are JSON objects, so this tag can never be mistaken for one.
    private static readonly byte[] AnchorTag = "anchor"u8.ToArray();

    private readonly byte[]? _key = string.IsNullOrEmpty(hmacKey) ? null : Encoding.UTF8.GetBytes(hmacKey);

    public string Compute(long sequence, string previous, ReadOnlySpan<byte> payload)
    {
        var header = Encoding.UTF8.GetBytes(string.Create(CultureInfo.InvariantCulture, $"{sequence}\n{previous}\n"));
        var input = new byte[header.Length + payload.Length];
        header.CopyTo(input, 0);
        payload.CopyTo(input.AsSpan(header.Length));
        var digest = _key is null ? SHA256.HashData(input) : HMACSHA256.HashData(_key, input);
        return Convert.ToHexString(digest);
    }

    /// <summary>Constant-time check that <paramref name="hash"/> is the link for the given entry.</summary>
    public bool IsValid(long sequence, string previous, string rawData, string hash) =>
        SameHash(Compute(sequence, previous, Encoding.UTF8.GetBytes(rawData)), hash);

    /// <summary>Signs an <see cref="AuditChainAnchor"/>: the last entry retention removed.</summary>
    public string SignAnchor(long sequence, string hash) => Compute(sequence, hash, AnchorTag);

    public bool IsValid(AuditChainAnchor anchor) =>
        SameHash(SignAnchor(anchor.Sequence, anchor.Hash), anchor.Signature);

    private static bool SameHash(string expected, string actual) =>
        CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(actual));
}
