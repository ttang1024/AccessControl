using System.Text.Json;
using System.Text.Json.Nodes;

namespace AccessControl.Application.Credentials;

/// <summary>
/// Hides card numbers in what the API returns. For most card technologies the number is all that is needed to
/// clone a card, so responses show only enough to tell cards apart: at most the last four characters, never more
/// than half, behind a fixed-length prefix that does not reveal the length.
/// </summary>
public static class CardNumberMask
{
    private const string InvalidPrefix = "invalid:";
    private const string Hidden = "****";

    /// <summary>Masks a canonical card number, or the <c>invalid:&lt;raw&gt;</c> form recorded for unparseable reads.</summary>
    public static string Mask(string cardNumber)
    {
        ArgumentNullException.ThrowIfNull(cardNumber);
        if (cardNumber.StartsWith(InvalidPrefix, StringComparison.Ordinal))
        {
            return InvalidPrefix + Mask(cardNumber[InvalidPrefix.Length..]);
        }

        var visible = Math.Min(4, cardNumber.Length / 2);
        return Hidden + cardNumber[^visible..];
    }

    /// <summary>A copy of a stored document with any <c>cardNumber</c> property masked.</summary>
    public static JsonElement? MaskDocument(JsonElement? document)
    {
        if (document is not { ValueKind: JsonValueKind.Object } value
            || !value.TryGetProperty("cardNumber", out var number)
            || number.ValueKind != JsonValueKind.String)
        {
            return document;
        }

        var node = JsonNode.Parse(value.GetRawText())!.AsObject();
        node["cardNumber"] = Mask(number.GetString()!);
        return JsonSerializer.SerializeToElement(node);
    }
}
