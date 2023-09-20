namespace ArchitectureDemo.Repositories;

public interface IUnitOfWork : IDisposable
{
    IUserRepository UserRepository { get; }
    
    //other repositories
    
    public Task<int> SaveChangesAsync(CancellationToken cancellationToken = new CancellationToken());    
}