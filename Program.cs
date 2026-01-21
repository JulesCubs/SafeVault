using SafeVault.Services;
using SafeVault.Security;
using SafeVault.Data;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

// Agregar servicios
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

builder.Services.AddScoped(_ => new UserRepository(connectionString));
builder.Services.AddScoped(_ => new SessionRepository(connectionString));
builder.Services.AddScoped(_ => new AuditLogRepository(connectionString));
builder.Services.AddScoped(_ => new RoleRepository(connectionString));

builder.Services.AddScoped<AuthenticationService>();
builder.Services.AddScoped<AuthorizationService>();

builder.Services.AddControllers();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

// Agregar middleware de autenticación
app.UseMiddleware<AuthenticationMiddleware>();

app.UseRouting();
app.UseEndpoints(endpoints => endpoints.MapControllers());

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets();

app.Run();
