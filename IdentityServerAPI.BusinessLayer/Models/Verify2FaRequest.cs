using System.ComponentModel.DataAnnotations;

namespace IdentityServerApi.BusinessLayer.Models;

public class Verify2FaRequest
{
    [Required]
    [StringLength(7, MinimumLength = 6, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.")]
    [DataType(DataType.Text)]
    public string Code { get; set; }
}