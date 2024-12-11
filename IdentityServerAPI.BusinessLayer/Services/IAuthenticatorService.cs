using IdentityServerApi.BusinessLayer.Models;

namespace IdentityServerApi.BusinessLayer.Services;

public interface IAuthenticatorService
{
    Task<GetAuthenticatorKeyResponse> GetAuthenticatorKeys();
    Task Enable2Fa(Enable2FaRequest request);
    Task Disable2Fa(bool resetAuthenticatorKey);
    Task Verify2Fa(Verify2FaRequest request);
    Task<IEnumerable<string>> GenerateRecoveryCodes();
}
