using ArchitectureDemo.Domain;

namespace ArchitectureDemo.Repositories;

public interface IUserRepository
{
    Task<User> GetUserByUsername(string username);
    
    //other methods
}