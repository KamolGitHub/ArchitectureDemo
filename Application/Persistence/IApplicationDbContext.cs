using Domain;
using Microsoft.EntityFrameworkCore;

namespace Application.Persistence;

public interface IApplicationDbContext
{
    public DbSet<User> Users { get; set; }
    
    public Task<int> SaveChangesAsync(CancellationToken cancellationToken = new CancellationToken());
}