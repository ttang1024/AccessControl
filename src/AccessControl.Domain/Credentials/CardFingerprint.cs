using AccessControl.Domain.Common;

namespace AccessControl.Domain.Credentials;

/// <summary>
/// What is kept of a card number. The number itself is a cloneable credential, so it is never stored: only a keyed
/// digest of its canonical form (for lookup and uniqueness) and a short hint (its last few digits, at most four, for
/// telling cards apart on screen). Computing the digest needs a secret, so it happens outside the domain.
/// </summary>
public readonly record struct CardFingerprint
{
    public const int DigestLength = 64;
    public const int MaxHintLength = 4;

    private CardFingerprint(string digest, string hint)
    {
        Digest = digest;
        Hint = hint;
    }

    /// <summary>Upper-case hex HMAC-SHA256 of the canonical card number.</summary>
    public string Digest { get; }

    /// <summary>The last digits shown to operators; may be empty for short card numbers.</summary>
    public string Hint { get; }

    public static CardFingerprint Create(string? digest, string? hint)
    {
        if (digest is null || digest.Length != DigestLength || !digest.All(c => char.IsAsciiHexDigitUpper(c) || char.IsAsciiDigit(c)))
        {
            throw DomainException.Validation("cardFingerprint.invalid_digest", $"A card digest is {DigestLength} upper-case hex characters.");
        }

        if (hint is null || hint.Length > MaxHintLength || !hint.All(char.IsAsciiHexDigit))
        {
            throw DomainException.Validation("cardFingerprint.invalid_hint", $"A card hint is at most {MaxHintLength} hex characters.");
        }

        return new CardFingerprint(digest, hint);
    }

    public override string ToString() => Digest ?? string.Empty;
}
