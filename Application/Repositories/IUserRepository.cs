using Domain;

namespace Application.Repositories;

public interface IUserRepository
{
    Task<User> GetUserByUsername(string username);
    
    //other methods
}