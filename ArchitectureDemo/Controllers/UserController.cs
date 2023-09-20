using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ArchitectureDemo.Persistence;
using ArchitectureDemo.Requests;
using ArchitectureDemo.Services;
using ArchitectureDemo.ViewModels;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace ArchitectureDemo.Controllers;

[ApiController]
[Route("[controller]")]
public class UserController : ControllerBase
{
    private readonly IUserService _userService;

    public UserController(IUserService userService)
    {
        _userService = userService;
    }

    [HttpPost("authenticate")]
    public async Task<IActionResult> Authenticate([FromBody] LoginRequest request)
    {
        var result = await _userService.Authenticate(request.Username, request.Password);

        return Ok(new LoginViewModel()
        {
            Token = result.token,
            Expiration = result.expiration
        });
    }

    public void Profile()
    {
    }
    
    public void UpdateProfile()
    {
    }
    
    public void Logout()
    {
    }
    
    //...
}