using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ArchitectureDemo.Domain;
using ArchitectureDemo.Persistence;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace ArchitectureDemo.Services;

public class UserService : IUserService
{
    private readonly IApplicationDbContext _applicationDbContext;
    private readonly INotifierService _notifierService;

    public UserService(IApplicationDbContext applicationDbContext, INotifierService notifierService)
    {
        _applicationDbContext = applicationDbContext;
        _notifierService = notifierService;
    }
    
    public async Task<(string token, DateTime expiration)> Authenticate(string username, string password)
    {
        var user = await _applicationDbContext.Users
                       .Where(x => x.Username == username)
                       .AsNoTracking()
                       .SingleOrDefaultAsync(CancellationToken.None) ??
                   throw new ValidationException("Введенный логин или пароль неверный.");

        if (!user.IsActive)
        {
            throw new ValidationException("Пользователь не активен!");
        }

        if (string.IsNullOrEmpty(password))
            throw new ArgumentException($"the {nameof(password)} value cannot be empty or null.");
        

        if (string.IsNullOrEmpty(user.Password))
            throw new ArgumentException($"the {nameof(user.Password)} value cannot be empty or null.");

        if (string.IsNullOrEmpty(user.PasswordSalt))
            throw new ArgumentException($"the {nameof(user.PasswordSalt)} value cannot be empty or null.");

        const string globalSalt = "someGlobalSalt";

        var saltBytes = Convert.FromBase64String(user.PasswordSalt);

        var passwordHash = Convert.ToBase64String(KeyDerivation.Pbkdf2(string.Concat(password, globalSalt),
            saltBytes, KeyDerivationPrf.HMACSHA256, 1000, 256 / 8));

        if (user.Password != passwordHash)
        {
            throw new ValidationException("Введенный логин или пароль неверный.");
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, username),
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("SecretKey"));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var jwtSecurityToken = new JwtSecurityToken(
            "Issuer",
            "Audience",
            claims,
            expires: DateTime.Now.AddMinutes(Convert.ToDouble("ExpirationInMinutes")),
            signingCredentials: credentials);

        var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        var expiration = jwtSecurityToken.ValidTo;

        await _notifierService.Send(user);
        
        return (token, expiration);
    }

    public Task<User> GetProfile()
    {
        throw new NotImplementedException();
    }

    public Task<User> UpdateProfile()
    {
        throw new NotImplementedException();
    }

    public Task<bool> Logout()
    {
        throw new NotImplementedException();
    }
}