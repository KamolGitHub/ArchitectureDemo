using ArchitectureDemo.Domain;

namespace ArchitectureDemo.Services;

public interface INotifierService
{
    Task Send(User user);
}