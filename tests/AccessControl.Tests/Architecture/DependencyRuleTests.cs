using System.Reflection;
using AccessControl.Application.Abstractions;
using AccessControl.Domain.Access;
using AccessControl.Infrastructure.Storage;
using Xunit;

namespace AccessControl.Tests.Architecture;

/// <summary>The layer rules from CLAUDE.md: dependencies point inward only.</summary>
public sealed class DependencyRuleTests
{
    private static readonly Assembly Domain = typeof(AccessEvaluator).Assembly;
    private static readonly Assembly Application = typeof(IUnitOfWork).Assembly;
    private static readonly Assembly Infrastructure = typeof(StorageOptions).Assembly;

    [Fact]
    public void Domain_references_nothing_but_the_runtime() =>
        Assert.All(References(Domain), name => Assert.True(
            name.StartsWith("System", StringComparison.Ordinal) || name == "netstandard",
            $"Domain references {name}"));

    [Fact]
    public void Application_references_only_the_domain_and_extension_abstractions() =>
        Assert.All(References(Application), name => Assert.True(
            name.StartsWith("System", StringComparison.Ordinal)
            || name == "AccessControl.Domain"
            || name.StartsWith("Microsoft.Extensions.", StringComparison.Ordinal),
            $"Application references {name}"));

    [Fact]
    public void Infrastructure_never_references_the_api_or_aspnetcore() =>
        Assert.All(References(Infrastructure), name => Assert.False(
            name == "AccessControl.Api" || name.StartsWith("Microsoft.AspNetCore", StringComparison.Ordinal),
            $"Infrastructure references {name}"));

    private static IEnumerable<string> References(Assembly assembly) =>
        assembly.GetReferencedAssemblies().Select(a => a.Name!);
}
