namespace ArchitectureDemo.Repositories;

public interface IUnitOfWork : IDisposable
{
    IUserRepository UserRepository { get; }
    
    //other repositories
    
    int SaveChanges();    
}