using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ArchitectureDemo.Domain;
using ArchitectureDemo.Repositories;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.IdentityModel.Tokens;

namespace ArchitectureDemo.Services;

public class UserService : IUserService
{
    private readonly IUnitOfWork _unitOfWork;
    private readonly INotifierService _notifierService;

    public UserService(IUnitOfWork unitOfWork, INotifierService notifierService)
    {
        _unitOfWork = unitOfWork;
        _notifierService = notifierService;
    }
    
    public async Task<(string token, DateTime expiration)> Authenticate(string username, string password)
    {
        var user = await _unitOfWork.UserRepository.GetUserByUsername(username);

        var isVerified = Verify(password, user.Password, user.PasswordSalt, "someGlobalSalt");

        if (!isVerified)
        {
            throw new ValidationException("Введенный логин или пароль неверный.");
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, username),
        };

        (var token, var expiration) = CreateToken(claims);

        await _notifierService.Send(user);
        
        return (token, expiration);
    }

    private bool Verify(string enteredPassword, string storedPassword, string storedSalt, string globalSalt)
    {
        const int iterationCount = 1000;
        const int numBytesRequested = 128/8;
        
        if (string.IsNullOrEmpty(enteredPassword))
            throw new ArgumentException("Value cannot be empty or null .", nameof(enteredPassword));

        if (string.IsNullOrEmpty(storedPassword))
            throw new ArgumentException("Value cannot be empty or null .", nameof(storedPassword));

        if (string.IsNullOrEmpty(storedSalt))
            throw new ArgumentException("Value cannot be empty or null .", nameof(storedSalt));

        if (string.IsNullOrEmpty(globalSalt))
            throw new ArgumentException("Value cannot be empty or null .", nameof(globalSalt));

        var saltBytes = Convert.FromBase64String(storedSalt);

        var passwordHash = Convert.ToBase64String(KeyDerivation.Pbkdf2(string.Concat(enteredPassword, globalSalt),
            saltBytes, KeyDerivationPrf.HMACSHA256, iterationCount, numBytesRequested));

        return passwordHash == storedPassword;
    }

    (string token, DateTime expiration) CreateToken(Claim[] claims)
    {
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