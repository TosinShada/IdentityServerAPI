using System.ComponentModel.DataAnnotations;

namespace IdentityServerApi.BusinessLayer.Models;

public class Disable2FaRequest
{
    [Required]
    [DataType(DataType.Text)]
    public bool ResetAuthenticatorKey { get; set; }
}