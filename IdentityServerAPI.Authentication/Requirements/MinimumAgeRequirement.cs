using Microsoft.AspNetCore.Authorization;

namespace IdentityServerApi.Authentication.Requirements;

public class MinimumAgeRequirement(int minimumAge) : IAuthorizationRequirement
{
    public int MinimumAge { get; } = minimumAge;
}
