namespace IdentityServerApi.BusinessLayer.Models;

public class AuthResponse
{
    public string AccessToken { get; set; }

    public string RefreshToken { get; set; }

    public bool IsTwoFaRequired { get; set; }
}
