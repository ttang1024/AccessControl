using AccessControl.Domain.Credentials;

namespace AccessControl.Application.Credentials;

/// <summary>
/// Turns a card number into what may be stored: a keyed digest and a display hint (see <see cref="CardFingerprint"/>).
/// The same number always gives the same fingerprint for a given key.
/// </summary>
public interface ICardNumberProtector
{
    CardFingerprint Protect(CardNumber cardNumber);
}
