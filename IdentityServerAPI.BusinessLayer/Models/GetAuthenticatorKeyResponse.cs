namespace IdentityServerApi.BusinessLayer.Models;

public class GetAuthenticatorKeyResponse
{
    public bool Succeeded { get; set; }

    public string SharedKey { get; set; }

    public string AuthenticatorUri { get; set; }

    public IEnumerable<string> Errors { get; set; }

    public GetAuthenticatorKeyResponse(string sharedKey, string authenticatorUri)
    {
        Succeeded = true;
        SharedKey = sharedKey;
        AuthenticatorUri = authenticatorUri;
    }
}
