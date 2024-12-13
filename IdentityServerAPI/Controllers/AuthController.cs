using IdentityServerApi.BusinessLayer.Models;
using IdentityServerApi.BusinessLayer.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServerApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(IIdentityService identityService) : ControllerBase
{
    [HttpPost("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login(LoginRequest request)
    {
        var response = await identityService.LoginAsync(request);
        if (response != null)
        {
            return Ok(response);
        }

        return BadRequest();
    }

    [HttpPost("login/all")]
    [AllowAnonymous]
    public async Task<IActionResult> LoginAll(LoginRequest request)
    {
        var response = await identityService.LoginAllAsync(request);
        if (response != null)
        {
            return Ok(response);
        }

        return BadRequest();
    }

    [HttpPost("login/2fa")]
    [AllowAnonymous]
    public async Task<IActionResult> LoginWith2Fa(TwoFaLoginRequest request)
    {
        var response = await identityService.LoginWith2FaAsync(request);
        if (response != null)
        {
            return Ok(response);
        }

        return BadRequest();
    }

    [HttpPost("impersonate")]
    public async Task<IActionResult> Impersonate(Guid userId)
    {
        var response = await identityService.ImpersonateAsync(userId);
        if (response is not null)
        {
            return Ok(response);
        }

        return BadRequest();
    }

    [AllowAnonymous]
    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshToken(RefreshTokenRequest request)
    {
        var response = await identityService.RefreshTokenAsync(request);
        if (response != null)
        {
            return Ok(response);
        }

        return BadRequest();
    }

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register(RegisterRequest request)
    {
        var response = await identityService.RegisterAsync(request);

        return StatusCode(response.Succeeded ? StatusCodes.Status200OK : StatusCodes.Status400BadRequest,
            response);

        //if (response.Succeeded)
        //{
        //    return Ok(response);
        //}

        //return BadRequest(response);
    }
}
