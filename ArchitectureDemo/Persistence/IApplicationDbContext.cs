using ArchitectureDemo.Domain;
using Microsoft.EntityFrameworkCore;

namespace ArchitectureDemo.Persistence;

public interface IApplicationDbContext
{
    public DbSet<User> Users { get; set; }
}