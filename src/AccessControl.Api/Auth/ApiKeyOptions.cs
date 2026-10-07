namespace AccessControl.Api.Auth;

public sealed class ApiKeyEntry
{
    /// <summary>Who holds the key. Unique; recorded as the actor in the change trail and shown in logs.</summary>
    public string Name { get; set; } = string.Empty;

    public string Role { get; set; } = string.Empty;

    /// <summary>Hex SHA-256 of the key. The plaintext key is never stored in configuration.</summary>
    public string Sha256 { get; set; } = string.Empty;

    /// <summary>
    /// <see cref="Roles.DoorController"/> keys only: the door ids this controller serves. Required, so a key
    /// stolen from one controller cannot be used to probe cards at other doors. <c>"*"</c> is allowed in
    /// Development only.
    /// </summary>
    public List<string> Doors { get; set; } = [];
}

public sealed class ApiKeyOptions
{
    public const string SectionName = "Auth";

    public List<ApiKeyEntry> ApiKeys { get; set; } = [];

    /// <summary>
    /// When true (default), API keys are rejected on plain-HTTP requests so they never cross the network in
    /// the clear. Behind a TLS-terminating proxy, enable forwarded headers so the original scheme is seen.
    /// </summary>
    public bool RequireHttps { get; set; } = true;

    /// <summary>Hashes of the keys published in CLAUDE.md. Refused outside the Development environment.</summary>
    internal static readonly IReadOnlySet<string> DevelopmentKeyHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "29b401073038b82dd8106b36b0e4105cb0fcf084a083efccb6f525c8973bd2d2",
        "6220ea9b7613b2d9cfcd89cce7e541308526d7a20dcea561b8c0c8d94f2d8908",
    };
}
