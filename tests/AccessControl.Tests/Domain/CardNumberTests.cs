using AccessControl.Domain.Common;
using AccessControl.Domain.Credentials;
using Xunit;

namespace AccessControl.Tests.Domain;

public sealed class CardNumberTests
{
    [Theory]
    [InlineData("0a1b2c", "0A1B2C")]
    [InlineData("0A:1B:2C", "0A1B2C")]
    [InlineData(" 12-34 56 ", "123456")]
    [InlineData("1", "1")]
    public void Parse_normalizes_to_uppercase_hex_without_separators(string raw, string expected)
    {
        Assert.Equal(expected, CardNumber.Parse(raw).Value);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("::--")]
    [InlineData("12G4")]
    [InlineData("123456789012345678901234567890123")] // 33 digits
    public void Parse_rejects_invalid_input(string raw)
    {
        var ex = Assert.Throws<DomainException>(() => CardNumber.Parse(raw));
        Assert.Equal("cardNumber.invalid", ex.Code);
        Assert.False(CardNumber.TryParse(raw, out _));
    }

    [Fact]
    public void Equivalent_spellings_are_equal()
    {
        Assert.Equal(CardNumber.Parse("ab:cd"), CardNumber.Parse("ABCD"));
    }

    [Fact]
    public void Leading_zeros_are_significant()
    {
        // Different widths can be different card formats: never merge them (fail closed).
        Assert.NotEqual(CardNumber.Parse("000A1B"), CardNumber.Parse("0A1B"));
        Assert.Equal("000A1B", CardNumber.Parse("00:0a:1b").Value);
    }
}
