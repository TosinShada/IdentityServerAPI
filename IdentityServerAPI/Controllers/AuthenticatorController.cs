using IdentityServerApi.BusinessLayer.Models;
using IdentityServerApi.BusinessLayer.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityServerApi.Controllers;

[Route("api/[controller]")]
[Authorize]
[ApiController]
public class AuthenticatorController(IAuthenticatorService authenticatorService) : ControllerBase
{
    [HttpGet("keys")]
    public async Task<IActionResult> GetAuthenticatorKeys()
    {
        var response = await authenticatorService.GetAuthenticatorKeys();
        return Ok(response);
    }

    [HttpPost("enable2fa")]
    public async Task<IActionResult> Enable2Fa(Enable2FaRequest request)
    {
        await authenticatorService.Enable2Fa(request);
        return Ok();
    }

    [HttpPost("disable2fa")]
    public async Task<IActionResult> Disable2Fa(Disable2FaRequest request)
    {
        await authenticatorService.Disable2Fa(request.ResetAuthenticatorKey);
        return Ok();
    }

    [HttpGet("recovery-codes")]
    public async Task<IActionResult> GenerateRecoveryCodes()
    {
        var response = await authenticatorService.GenerateRecoveryCodes();
        return Ok(response);
    }

    [HttpPost("verify2fa")]
    public async Task<IActionResult> Verify2Fa(Verify2FaRequest request)
    {
        await authenticatorService.Verify2Fa(request);
        return Ok();
    }
}
