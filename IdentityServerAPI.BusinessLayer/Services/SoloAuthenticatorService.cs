using Google.Authenticator;
using IdentityServerApi.Authentication.Entities;
using IdentityServerApi.BusinessLayer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace IdentityServerApi.BusinessLayer.Services;

public class SoloAuthenticatorService(
    UserManager<ApplicationUser> userManager,
    IUserService userService,
    ILogger<SoloAuthenticatorService> logger) : IAuthenticatorService
{
    private const string SecretKey = "JBSWY3DPEHPK3PXP";
    private const string TestIssuer = "TestIssuer";
    public async Task<GetAuthenticatorKeyResponse> GetAuthenticatorKeys()
    {
        var userPrincipal = userService.GetUser() ?? throw new InvalidOperationException("User not found.");
        var user = await userManager.GetUserAsync(userPrincipal) ?? throw new InvalidOperationException("User not found.");

        if (string.IsNullOrEmpty(user.Email))
        {
            throw new InvalidOperationException("User does not have an email address.");
        }

        var is2FaEnabled = await userManager.GetTwoFactorEnabledAsync(user);
        if (is2FaEnabled)
        {
            throw new InvalidOperationException("2FA is already enabled.");
        }

        var setup2FaResponse = Setup2fa(user.Email);

        var usernameNoSpaces = RemoveWhitespace(Uri.EscapeDataString(user.Email));

        var provisionUrl = $"otpauth://totp/{TestIssuer}:{usernameNoSpaces}?secret={setup2FaResponse.ManualKey}&issuer={TestIssuer}&algorithm=SHA256";

        return new GetAuthenticatorKeyResponse(setup2FaResponse.ManualKey, provisionUrl);

        static string RemoveWhitespace(string str) =>
            new string(str.Where(c => !char.IsWhiteSpace(c)).ToArray());
    }

    public async Task Enable2Fa(Enable2FaRequest request) => throw new NotImplementedException();

    public async Task Disable2Fa(bool resetAuthenticatorKey) => throw new NotImplementedException();

    public async Task Verify2Fa(Verify2FaRequest request)
    {
        // Strip spaces and hyphens
        var verificationCode = request.Code.Replace(" ", string.Empty).Replace("-", string.Empty);

        var tfA = new TwoFactorAuthenticator(HashType.SHA256);
        var is2FaTokenValid = tfA.ValidateTwoFactorPIN(SecretKey, verificationCode);

        if (!is2FaTokenValid)
        {
            throw new InvalidOperationException("Verification code is invalid.");
        }
    }

    public async Task<IEnumerable<string>> GenerateRecoveryCodes() => throw new NotImplementedException();

    private Setup2FaResponse Setup2fa(string username)
    {
        var tfA = new TwoFactorAuthenticator(HashType.SHA256);
        var setupCode = tfA.GenerateSetupCode(TestIssuer, username, SecretKey, false, 3);

        return new Setup2FaResponse
        {
            QrImage = setupCode.QrCodeSetupImageUrl,
            ManualKey = setupCode.ManualEntryKey,
            SecretKey = SecretKey
        };
    }
}
