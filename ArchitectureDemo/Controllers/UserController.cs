using Application.Commands;
using Application.Services;
using ArchitectureDemo.Requests;
using ArchitectureDemo.ViewModels;
using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace ArchitectureDemo.Controllers;

[ApiController]
[Route("[controller]")]
public class UserController : ControllerBase
{
    private readonly IMediator _mediator;

    public UserController(IMediator mediator)
    {
        _mediator = mediator;
    }

    [HttpPost("authenticate")]
    public async Task<IActionResult> Authenticate([FromBody] LoginRequest request)
    {
        var result = await _mediator.Send(new AuthenticateUserCommand()
        {
            Username = request.Username,
            Password = request.Password
        });

        return Ok(new LoginViewModel()
        {
            Token = result.token,
            Expiration = result.expiration
        });
    }

    public void Profile()
    {
    }
    
    public void UpdateProfile()
    {
    }
    
    public void Logout()
    {
    }
    
    //...
}