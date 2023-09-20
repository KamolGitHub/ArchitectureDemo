using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ArchitectureDemo.Persistence;
using ArchitectureDemo.Requests;
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
    private readonly IApplicationDbContext _applicationDbContext;

    public UserController(IApplicationDbContext applicationDbContext)
    {
        _applicationDbContext = applicationDbContext;
    }

    [HttpPost("authenticate")]
    public async Task<IActionResult> Authenticate([FromBody] LoginRequest request)
    {
        var user = await _applicationDbContext.Users
                       .Where(x => x.Username == request.Username)
                       .AsNoTracking()
                       .SingleOrDefaultAsync(CancellationToken.None) ??
                   throw new ValidationException("Введенный логин или пароль неверный.");

        if (!user.IsActive)
        {
            throw new ValidationException("Пользователь не активен!");
        }

        if (string.IsNullOrEmpty(request.Password))
            throw new ArgumentException($"the {nameof(request.Password)} value cannot be empty or null.");
        

        if (string.IsNullOrEmpty(user.Password))
            throw new ArgumentException($"the {nameof(user.Password)} value cannot be empty or null.");

        if (string.IsNullOrEmpty(user.PasswordSalt))
            throw new ArgumentException($"the {nameof(user.PasswordSalt)} value cannot be empty or null.");

        const string globalSalt = "someGlobalSalt";

        var saltBytes = Convert.FromBase64String(user.PasswordSalt);

        var passwordHash = Convert.ToBase64String(KeyDerivation.Pbkdf2(string.Concat(request.Password, globalSalt),
            saltBytes, KeyDerivationPrf.HMACSHA256, 1000, 256 / 8));

        if (user.Password != passwordHash)
        {
            throw new ValidationException("Введенный логин или пароль неверный.");
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, request.Username),
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SecretKey"));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            "Issuer",
            "Audience",
            claims,
            expires: DateTime.Now.AddMinutes(Convert.ToDouble("ExpirationInMinutes")),
            signingCredentials: credentials);

        //call EmailSender to send notification
        
        return Ok(new LoginViewModel()
        {
            Token = new JwtSecurityTokenHandler().WriteToken(token),
            Expiration = token.ValidTo
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