using BasisNetworkServer.Security;
using Xunit;

namespace BasisServerTests;

public class ServerDidIdentityTests
{
    [Fact]
    public void GenerateDidKey_ReturnsAResolvableDidKey()
    {
        string serverId = BasisServerDIDIdentity.GenerateDidKey();

        Assert.True(BasisServerDIDIdentity.IsValidDidKey(serverId));
    }

    [Theory]
    [InlineData("")]
    [InlineData("did:key:not-base58")]
    [InlineData("did:example:server")]
    public void IsValidDidKey_RejectsMalformedIdentifiers(string serverId)
    {
        Assert.False(BasisServerDIDIdentity.IsValidDidKey(serverId));
    }
}
