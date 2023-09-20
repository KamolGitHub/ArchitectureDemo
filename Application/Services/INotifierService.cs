using Domain;

namespace Application.Services;

public interface INotifierService
{
    Task Send(User user);
}