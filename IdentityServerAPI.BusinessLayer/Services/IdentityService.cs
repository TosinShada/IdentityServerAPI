using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using IdentityServerApi.Authentication;
using IdentityServerApi.Authentication.Entities;
using IdentityServerApi.Authentication.Extensions;
using IdentityServerApi.BusinessLayer.Models;
using IdentityServerApi.BusinessLayer.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServerApi.BusinessLayer.Services;

public class IdentityService(
    IOptions<JwtSettings> jwtSettingsOptions,
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    IUserService userService,
    ILogger<IdentityService> logger) : IIdentityService
{
    private readonly JwtSettings jwtSettings = jwtSettingsOptions.Value;

    public async Task<AuthResponse> LoginAsync(LoginRequest request)
    {
        var signInResult = await signInManager.PasswordSignInAsync(request.UserName, request.Password, false, false);

        if (signInResult.RequiresTwoFactor)
        {
            return new AuthResponse { IsTwoFaRequired = true };
            // var authenticatorCode = request.TwoFactorCode?.Replace(" ", string.Empty).Replace("-", string.Empty) ??
            //                         throw new InvalidOperationException("Invalid authenticator code");
            //
            // var twoFaSignInResult = await signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, false, false);
            // if (!twoFaSignInResult.Succeeded)
            // {
            //     return null;
            // }
        }

        if (!signInResult.Succeeded)
        {
            return null;
        }

        var user = await userManager.FindByNameAsync(request.UserName);
        await userManager.UpdateSecurityStampAsync(user);

        var userRoles = await userManager.GetRolesAsync(user);

        var claims = new List<Claim>()
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, request.UserName),
            new(ClaimTypes.GivenName, user.FirstName),
            new(ClaimTypes.Surname, user.LastName ?? string.Empty),
            new(ClaimTypes.Email, user.Email ?? string.Empty),
            new(ClaimTypes.SerialNumber, user.SecurityStamp ?? string.Empty)
        }.Union(userRoles.Select(role => new Claim(ClaimTypes.Role, role))).ToList();

        var loginResponse = CreateToken(claims);

        loginResponse.IsTwoFaRequired = signInResult.RequiresTwoFactor;

        user.RefreshToken = loginResponse.RefreshToken;
        user.RefreshTokenExpirationDate = DateTime.UtcNow.AddMinutes(jwtSettings.RefreshTokenExpirationMinutes);

        await userManager.UpdateAsync(user);

        return loginResponse;
    }

    public async Task<AuthResponse> LoginAllAsync(LoginRequest request)
    {
        var signInResult = await signInManager.PasswordSignInAsync(request.UserName, request.Password, false, false);

        if (signInResult.RequiresTwoFactor)
        {
            var authenticatorCode = request.TwoFactorCode?.Replace(" ", string.Empty).Replace("-", string.Empty) ??
                                    throw new InvalidOperationException("Invalid authenticator code");

            var twoFaSignInResult =
                await signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, false, false);
            if (!twoFaSignInResult.Succeeded)
            {
                return null;
            }
        }
        else if (!signInResult.Succeeded)
        {
            return null;
        }

        var user = await userManager.FindByNameAsync(request.UserName);
        await userManager.UpdateSecurityStampAsync(user);

        var userRoles = await userManager.GetRolesAsync(user);

        var claims = new List<Claim>()
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, request.UserName),
            new(ClaimTypes.GivenName, user.FirstName),
            new(ClaimTypes.Surname, user.LastName ?? string.Empty),
            new(ClaimTypes.Email, user.Email ?? string.Empty),
            new(ClaimTypes.SerialNumber, user.SecurityStamp ?? string.Empty)
        }.Union(userRoles.Select(role => new Claim(ClaimTypes.Role, role))).ToList();

        var loginResponse = CreateToken(claims);

        loginResponse.IsTwoFaRequired = signInResult.RequiresTwoFactor;

        user.RefreshToken = loginResponse.RefreshToken;
        user.RefreshTokenExpirationDate = DateTime.UtcNow.AddMinutes(jwtSettings.RefreshTokenExpirationMinutes);

        await userManager.UpdateAsync(user);

        return loginResponse;
    }

    public async Task<AuthResponse> LoginWith2FaAsync(TwoFaLoginRequest request)
    {
        var user = await signInManager.GetTwoFactorAuthenticationUserAsync();
        if (user == null)
        {
            throw new InvalidOperationException("Unable to load user.");
        }

        var authenticatorCode = request.TwoFactorCode?.Replace(" ", string.Empty).Replace("-", string.Empty) ??
                                throw new InvalidOperationException("Invalid authenticator code");

        var twoFaSignInResult = await signInManager.TwoFactorAuthenticatorSignInAsync(authenticatorCode, false, false);
        if (!twoFaSignInResult.Succeeded)
        {
            return null;
        }

        var userRoles = await userManager.GetRolesAsync(user);

        var claims = new List<Claim>()
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.UserName ?? string.Empty),
            new(ClaimTypes.GivenName, user.FirstName),
            new(ClaimTypes.Surname, user.LastName ?? string.Empty),
            new(ClaimTypes.Email, user.Email ?? string.Empty),
            new(ClaimTypes.SerialNumber, user.SecurityStamp ?? string.Empty)
        }.Union(userRoles.Select(role => new Claim(ClaimTypes.Role, role))).ToList();

        var loginResponse = CreateToken(claims);

        user.RefreshToken = loginResponse.RefreshToken;
        user.RefreshTokenExpirationDate = DateTime.UtcNow.AddMinutes(jwtSettings.RefreshTokenExpirationMinutes);

        await userManager.UpdateAsync(user);

        return loginResponse;
    }

    public async Task<AuthResponse> ImpersonateAsync(Guid userId)
    {
        var user = await userManager.FindByIdAsync(userId.ToString());
        if (user is null || user.LockoutEnd.GetValueOrDefault() > DateTimeOffset.UtcNow)
        {
            return null;
        }

        await userManager.UpdateSecurityStampAsync(user);
        var identity = userService.GetIdentity();

        UpdateClaim(ClaimTypes.NameIdentifier, user.Id.ToString());
        UpdateClaim(ClaimTypes.Name, user.UserName);
        UpdateClaim(ClaimTypes.GivenName, user.FirstName);
        UpdateClaim(ClaimTypes.Surname, user.LastName ?? string.Empty);
        UpdateClaim(ClaimTypes.Email, user.Email);
        UpdateClaim(ClaimTypes.SerialNumber, user.SecurityStamp ?? string.Empty);

        var loginResponse = CreateToken(identity.Claims.ToList());

        user.RefreshToken = loginResponse.RefreshToken;
        user.RefreshTokenExpirationDate = DateTime.UtcNow.AddMinutes(jwtSettings.RefreshTokenExpirationMinutes);

        await userManager.UpdateAsync(user);

        return loginResponse;

        void UpdateClaim(string type, string value)
        {
            var existingClaim = identity.FindFirst(type);
            if (existingClaim is not null)
            {
                identity.RemoveClaim(existingClaim);
            }

            identity.AddClaim(new Claim(type, value));
        }
    }

    public async Task<AuthResponse> RefreshTokenAsync(RefreshTokenRequest request)
    {
        var user = ValidateAccessToken(request.AccessToken);
        if (user != null)
        {
            var userId = user.GetId();
            var dbUser = await userManager.FindByIdAsync(userId.ToString());

            if (dbUser?.RefreshToken == null || dbUser?.RefreshTokenExpirationDate < DateTime.UtcNow ||
                dbUser?.RefreshToken != request.RefreshToken)
            {
                return null;
            }

            var loginResponse = CreateToken(user.Claims.ToList());

            dbUser.RefreshToken = loginResponse.RefreshToken;
            dbUser.RefreshTokenExpirationDate = DateTime.UtcNow.AddMinutes(jwtSettings.RefreshTokenExpirationMinutes);

            await userManager.UpdateAsync(dbUser);

            return loginResponse;
        }

        return null;
    }

    public async Task<RegisterResponse> RegisterAsync(RegisterRequest request)
    {
        var user = new ApplicationUser
        {
            FirstName = request.FirstName,
            LastName = request.LastName,
            Email = request.Email,
            UserName = request.Email
        };

        var result = await userManager.CreateAsync(user, request.Password);
        if (result.Succeeded)
        {
            result = await userManager.AddToRoleAsync(user, RoleNames.User);
        }

        var response = new RegisterResponse
        {
            Succeeded = result.Succeeded, Errors = result.Errors.Select(e => e.Description)
        };

        return response;
    }

    private AuthResponse CreateToken(IList<Claim> claims)
    {
        var audienceClaim = claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Aud);
        claims.Remove(audienceClaim);

        var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecurityKey));
        var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

        var jwtSecurityToken = new JwtSecurityToken(jwtSettings.Issuer, jwtSettings.Audience, claims,
            DateTime.UtcNow, DateTime.UtcNow.AddMinutes(jwtSettings.AccessTokenExpirationMinutes), signingCredentials);

        var accessToken = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

        var response = new AuthResponse { AccessToken = accessToken, RefreshToken = GenerateRefreshToken() };

        return response;

        static string GenerateRefreshToken()
        {
            var randomNumber = new byte[256];
            using var generator = RandomNumberGenerator.Create();
            generator.GetBytes(randomNumber);

            return Convert.ToBase64String(randomNumber);
        }
    }

    private ClaimsPrincipal ValidateAccessToken(string accessToken)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtSettings.Issuer,
            ValidateAudience = true,
            ValidAudience = jwtSettings.Audience,
            ValidateLifetime = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecurityKey)),
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.Zero
        };

        var tokenHandler = new JwtSecurityTokenHandler();

        try
        {
            var user = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out var securityToken);
            if (securityToken is JwtSecurityToken jwtSecurityToken &&
                jwtSecurityToken.Header.Alg == SecurityAlgorithms.HmacSha256)
            {
                return user;
            }
        }
        catch (Exception ex)
        {
            logger.LogError("Error validating access token: {Message}", ex.Message);
        }

        return null;
    }
}