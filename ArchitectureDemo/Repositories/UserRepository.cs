using System.ComponentModel.DataAnnotations;
using ArchitectureDemo.Domain;
using ArchitectureDemo.Persistence;
using Microsoft.EntityFrameworkCore;

namespace ArchitectureDemo.Repositories;

public class UserRepository : IUserRepository
{
    private readonly IApplicationDbContext _applicationDbContext;

    public UserRepository(IApplicationDbContext applicationDbContext)
    {
        _applicationDbContext = applicationDbContext;
    }
    
    public async Task<User> GetUserByUsername(string username)
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

        return user;
    }
}