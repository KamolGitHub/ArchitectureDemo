namespace ArchitectureDemo.Common;

public interface IEndpoint
{
    void AddRoute(IEndpointRouteBuilder app);
}