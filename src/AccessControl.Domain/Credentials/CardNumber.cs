using AccessControl.Domain.Common;

namespace AccessControl.Domain.Credentials;

/// <summary>
/// The identifier a reader sends for a card, in a canonical form (upper-case hexadecimal, no separators) so that
/// "0a:1b" and "0A1B" match. Leading zeros are kept: readers send a fixed number of bits per card format, so "000A1B"
/// and "0A1B" may be different cards, and treating them as one could let a card open another's doors. A reader that
/// sends the same card with a different width is misconfigured; its reads are denied and audited as unknown cards.
/// </summary>
public readonly record struct CardNumber
{
    public const int MaxLength = 32;

    private CardNumber(string value) => Value = value;

    public string Value { get; }

    public static CardNumber Parse(string? raw)
    {
        if (TryParse(raw, out var cardNumber))
        {
            return cardNumber;
        }

        throw DomainException.Validation(
            "cardNumber.invalid",
            $"Card number must be 1-{MaxLength} hexadecimal digits (separators ':', '-' and spaces are ignored).");
    }

    public static bool TryParse(string? raw, out CardNumber cardNumber)
    {
        cardNumber = default;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        Span<char> buffer = stackalloc char[MaxLength];
        var length = 0;
        foreach (var c in raw)
        {
            if (c is ':' or '-' or ' ')
            {
                continue;
            }

            if (!char.IsAsciiHexDigit(c) || length == MaxLength)
            {
                return false;
            }

            buffer[length++] = char.ToUpperInvariant(c);
        }

        if (length == 0)
        {
            return false;
        }

        cardNumber = new CardNumber(new string(buffer[..length]));
        return true;
    }

    public override string ToString() => Value ?? string.Empty;
}
