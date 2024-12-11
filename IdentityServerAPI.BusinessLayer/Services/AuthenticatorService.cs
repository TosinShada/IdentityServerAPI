using System.Text;
using System.Text.Encodings.Web;
using IdentityServerApi.Authentication.Entities;
using IdentityServerApi.BusinessLayer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace IdentityServerApi.BusinessLayer.Services;

public class AuthenticatorService(
    UserManager<ApplicationUser> userManager,
    IUserService userService,
    ILogger<AuthenticatorService> logger,
    UrlEncoder urlEncoder,
    SignInManager<ApplicationUser> signInManager) : IAuthenticatorService
{
    private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

    public async Task<GetAuthenticatorKeyResponse> GetAuthenticatorKeys()
    {
        var userPrincipal = userService.GetUser() ?? throw new InvalidOperationException("User not found.");
        var user = await userManager.GetUserAsync(userPrincipal) ?? throw new InvalidOperationException("User not found.");

        var is2FaEnabled = await userManager.GetTwoFactorEnabledAsync(user);
        if (is2FaEnabled)
        {
            throw new InvalidOperationException("2FA is already enabled.");
        }

        // Load the authenticator key & QR code URI to display on the form
        var unformattedKey = await userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(unformattedKey))
        {
            await userManager.ResetAuthenticatorKeyAsync(user);
            unformattedKey = await userManager.GetAuthenticatorKeyAsync(user);
        }

        var sharedKey = FormatKey(unformattedKey);

        var email = await userManager.GetEmailAsync(user);
        var authenticatorUri = GenerateQrCodeUri(email, unformattedKey);

        return new GetAuthenticatorKeyResponse(sharedKey, authenticatorUri);
    }

    public async Task Enable2Fa(Enable2FaRequest request)
    {
        var userPrincipal = userService.GetUser() ?? throw new InvalidOperationException("User not found.");
        var user = await userManager.GetUserAsync(userPrincipal) ?? throw new InvalidOperationException("User not found.");

        var is2FaEnabled = await userManager.GetTwoFactorEnabledAsync(user);
        if (is2FaEnabled)
        {
            throw new InvalidOperationException("2FA is already enabled.");
        }

        // Strip spaces and hyphens
        var verificationCode = request.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

        var is2FaTokenValid = await userManager.VerifyTwoFactorTokenAsync(
            user, userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

        if (!is2FaTokenValid)
        {
            throw new InvalidOperationException("Verification code is invalid.");
        }

        await userManager.SetTwoFactorEnabledAsync(user, true);
        await signInManager.RefreshSignInAsync(user);
    }

    public async Task Disable2Fa(bool resetAuthenticatorKey)
    {
        var userPrincipal = userService.GetUser() ?? throw new InvalidOperationException("User not found.");
        var user = await userManager.GetUserAsync(userPrincipal) ?? throw new InvalidOperationException("User not found.");

        await userManager.SetTwoFactorEnabledAsync(user, false);
        if (resetAuthenticatorKey)
        {
            await userManager.ResetAuthenticatorKeyAsync(user);
            await signInManager.RefreshSignInAsync(user);
        }
        logger.LogInformation("User with ID '{UserId}' has disabled 2fa.", user.Id);
    }

    public async Task<IEnumerable<string>> GenerateRecoveryCodes()
    {
        var userPrincipal = userService.GetUser() ?? throw new InvalidOperationException("User not found.");
        var user = await userManager.GetUserAsync(userPrincipal) ?? throw new InvalidOperationException("User not found.");

        var isTwoFactorEnabled = await userManager.GetTwoFactorEnabledAsync(user);
        if (!isTwoFactorEnabled)
        {
            throw new InvalidOperationException("Cannot generate recovery codes for user as they do not have 2FA enabled.");
        }

        var recoveryCodes = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);

        return recoveryCodes;
    }

    public async Task Verify2Fa(Verify2FaRequest request)
    {
        var userPrincipal = userService.GetUser() ?? throw new InvalidOperationException("User not found.");
        var user = await userManager.GetUserAsync(userPrincipal) ?? throw new InvalidOperationException("User not found.");

        var is2FaEnabled = await userManager.GetTwoFactorEnabledAsync(user);
        if (!is2FaEnabled)
        {
            throw new InvalidOperationException("2FA is not enabled.");
        }

        // Strip spaces and hyphens
        var verificationCode = request.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

        var is2FaTokenValid = await userManager.VerifyTwoFactorTokenAsync(
            user, userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);

        if (!is2FaTokenValid)
        {
            throw new InvalidOperationException("Verification code is invalid.");
        }
    }

    private string FormatKey(string unformattedKey)
    {
        var result = new StringBuilder();
        int currentPosition = 0;
        while (currentPosition + 4 < unformattedKey.Length)
        {
            result.Append(unformattedKey.Substring(currentPosition, 4)).Append(" ");
            currentPosition += 4;
        }
        if (currentPosition < unformattedKey.Length)
        {
            result.Append(unformattedKey.Substring(currentPosition));
        }

        return result.ToString().ToLowerInvariant();
    }

    private string GenerateQrCodeUri(string email, string unformattedKey)
    {
        return string.Format(
            AuthenticatorUriFormat,
            urlEncoder.Encode("IdentityStandaloneMfa"),
            urlEncoder.Encode(email),
            unformattedKey);
    }
}
