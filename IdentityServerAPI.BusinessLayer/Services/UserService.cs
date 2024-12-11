using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace IdentityServerApi.BusinessLayer.Services;

public class UserService(IHttpContextAccessor httpContextAccessor) : IUserService
{
    public string GetUserName() => httpContextAccessor.HttpContext?.User.Identity?.Name;

    public ClaimsIdentity GetIdentity() => httpContextAccessor.HttpContext?.User.Identity as ClaimsIdentity;

    public ClaimsPrincipal? GetUser() => httpContextAccessor.HttpContext?.User;
}
