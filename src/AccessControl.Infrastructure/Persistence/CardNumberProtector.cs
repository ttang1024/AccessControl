using System.Security.Cryptography;
using System.Text;
using AccessControl.Application.Credentials;
using AccessControl.Domain.Credentials;
using AccessControl.Infrastructure.Storage;
using Microsoft.Extensions.Options;

namespace AccessControl.Infrastructure.Persistence;

/// <summary>
/// HMAC-SHA256 of the canonical card number under <see cref="StorageOptions.CardNumberKey"/>. Without the key, the
/// digests of a short card space could be computed for every possible number, so the key is required outside
/// Development; there an unkeyed, domain-separated SHA-256 is used instead.
/// </summary>
internal sealed class CardNumberProtector(IOptions<StorageOptions> options) : ICardNumberProtector
{
    private static readonly byte[] UnkeyedPrefix = "access-control/card-number/v1\n"u8.ToArray();

    private readonly byte[]? _key = string.IsNullOrEmpty(options.Value.CardNumberKey)
        ? null
        : Encoding.UTF8.GetBytes(options.Value.CardNumberKey);

    public CardFingerprint Protect(CardNumber cardNumber)
    {
        var number = Encoding.ASCII.GetBytes(cardNumber.Value);
        var digest = _key is null ? SHA256.HashData([.. UnkeyedPrefix, .. number]) : HMACSHA256.HashData(_key, number);
        return CardFingerprint.Create(Convert.ToHexString(digest), CardNumberMask.VisibleTail(cardNumber.Value));
    }
}
