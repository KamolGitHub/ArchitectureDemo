namespace ArchitectureDemo.Features.Identities.Authenticate;

public class Response
{
    public string Token { get; set; }
    public DateTime Expiration { get; set; }
}