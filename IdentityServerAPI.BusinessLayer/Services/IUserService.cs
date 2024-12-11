using System.Security.Claims;

namespace IdentityServerApi.BusinessLayer.Services;

public interface IUserService
{
    string GetUserName();

    public ClaimsIdentity GetIdentity();

    public ClaimsPrincipal? GetUser();
}
