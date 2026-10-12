using System.Globalization;
using AccessControl.Application.Abstractions;
using AccessControl.Application.Errors;

namespace AccessControl.Api.Endpoints;

/// <summary>
/// Resource versions as HTTP entity tags. Every response carrying an <see cref="IVersioned"/> resource gets
/// <c>ETag: "&lt;version&gt;"</c>; a write may send it back as <c>If-Match</c>, and fails with 412 if the resource has
/// changed since, instead of silently overwriting a change the client never saw. <c>If-Match</c> is optional.
/// </summary>
internal static class ETags
{
    public const string IfMatchHeader = "If-Match";

    public static string Format(int version) => string.Create(CultureInfo.InvariantCulture, $"\"{version}\"");

    /// <summary>The version in an <c>If-Match</c> header; <c>null</c> when absent or <c>*</c>.</summary>
    /// <exception cref="RequestValidationException">Not a single entity tag this API issued.</exception>
    public static int? ParseIfMatch(string? header)
    {
        var value = header?.Trim();
        if (string.IsNullOrEmpty(value) || value == "*")
        {
            return null;
        }

        if (value.StartsWith("W/", StringComparison.Ordinal))
        {
            value = value[2..];
        }

        if (value.Length > 2 && value[0] == '"' && value[^1] == '"'
            && int.TryParse(value.AsSpan(1, value.Length - 2), NumberStyles.None, CultureInfo.InvariantCulture, out var version))
        {
            return version;
        }

        throw new RequestValidationException("if_match.invalid", "If-Match must be one entity tag from an ETag header, e.g. \"3\".");
    }

    /// <summary>Adds <c>ETag</c> to responses whose body is a versioned resource.</summary>
    public static RouteGroupBuilder WithETags(this RouteGroupBuilder group)
    {
        group.AddEndpointFilter(async (context, next) =>
        {
            var result = await next(context).ConfigureAwait(false);
            var value = result is IValueHttpResult { Value: var inner } ? inner : result;
            if (value is IVersioned versioned)
            {
                context.HttpContext.Response.Headers.ETag = Format(versioned.Version);
            }

            return result;
        });
        return group;
    }
}
