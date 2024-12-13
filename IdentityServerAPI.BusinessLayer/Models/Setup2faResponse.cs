namespace IdentityServerApi.BusinessLayer.Models;

public class Setup2FaResponse
{
    public string QrImage { get; set; } = string.Empty;
    public string ManualKey { get; set; } = string.Empty;
    public string SecretKey { get; set; } = string.Empty;
}