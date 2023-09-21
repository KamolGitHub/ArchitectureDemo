using ArchitectureDemo.Common;
using AuthenticateEndpoint = ArchitectureDemo.Features.Identities.Authenticate.Endpoint;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddScoped<IEndpoint, AuthenticateEndpoint>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

#region repr+vertical_slice
var endpoints= app.Services.GetServices<IEndpoint>();
foreach (var endpoint in endpoints)
{
    endpoint.AddRoute(app);
}
#endregion


app.Run();