namespace ArchitectureDemo.Endpoints;

public interface IEndpoint
{
    void AddRoute(IEndpointRouteBuilder app);
}