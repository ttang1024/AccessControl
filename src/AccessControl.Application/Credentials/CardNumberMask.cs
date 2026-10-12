namespace AccessControl.Application.Credentials;

/// <summary>
/// How much of a card number people may see. For most card technologies the number is all that is needed to clone a
/// card, and short formats make every digit count: a 26-bit Wiegand card is a site-wide facility code plus a 16-bit
/// number (four hex digits), so showing "the last four" would show the whole card. The tail shown therefore depends
/// on the length: four hex digits only from 64 bits up, two from 32 bits up, none below that.
/// </summary>
public static class CardNumberMask
{
    private const string InvalidPrefix = "invalid:";
    private const string Hidden = "****";

    /// <summary>The trailing characters of a canonical card number that may be shown.</summary>
    public static string VisibleTail(string cardNumber)
    {
        ArgumentNullException.ThrowIfNull(cardNumber);
        var visible = cardNumber.Length switch
        {
            >= 16 => 4,
            >= 8 => 2,
            _ => 0,
        };
        return cardNumber[^visible..];
    }

    /// <summary>The display form of a stored hint, e.g. <c>****1234</c>.</summary>
    public static string Display(string hint) => Hidden + hint;

    /// <summary>Masks a card number (or any reader input) to its display form, e.g. <c>****34</c>.</summary>
    public static string Mask(string cardNumber) => Display(VisibleTail(cardNumber));

    /// <summary>The display form recorded for reader input that is not a card number, e.g. <c>invalid:****rd</c>.</summary>
    public static string Invalid(string raw) => InvalidPrefix + Mask(raw);
}
