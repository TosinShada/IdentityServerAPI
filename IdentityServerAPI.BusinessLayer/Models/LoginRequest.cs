namespace IdentityServerApi.BusinessLayer.Models;

public class LoginRequest
{
    public string UserName { get; set; }

    public string Password { get; set; }

    public string? TwoFactorCode { get; set; }
}
