using IdentityServerApi.BusinessLayer.Models;

namespace IdentityServerApi.BusinessLayer.Services;

public interface IIdentityService
{
    Task<RegisterResponse> RegisterAsync(RegisterRequest request);

    Task<AuthResponse> LoginAsync(LoginRequest request);

    Task<AuthResponse> LoginWith2FaAsync(TwoFaLoginRequest request);

    Task<AuthResponse> RefreshTokenAsync(RefreshTokenRequest request);

    Task<AuthResponse> ImpersonateAsync(Guid userId);
}
