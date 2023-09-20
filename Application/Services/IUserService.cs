using Domain;

namespace Application.Services;

public interface IUserService
{
    Task<(string token, DateTime expiration)> Authenticate(string username, string password);
    Task<User> GetProfile();
    Task<User> UpdateProfile();
    Task<bool> Logout();
}