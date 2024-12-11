using IdentityServerApi.Authentication.Extensions;
using IdentityServerApi.BusinessLayer.Models;
using IdentityServerApi.BusinessLayer.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServerApi.Controllers;

[Route("api/[controller]")]
[ApiController]
public class MeController : ControllerBase
{
    [Authorize]
    [HttpGet]
    public IActionResult GetMe([FromServices] IUserService userService)
    {
        var user = new User
        {
            Id = User.GetId(),
            FirstName = User.GetFirstName(),
            LastName = User.GetLastName(),
            Email = User.GetEmail()
        };

        return Ok(user);
    }
}
