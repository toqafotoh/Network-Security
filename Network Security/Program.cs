using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Network_Security.Middlewares;
using NetworkSecurityApp.Data;
using NetworkSecurityApp.Services;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Configure the database context using the connection string from configuration
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Register encryption service (AES) and JWT service for dependency injection
builder.Services.AddScoped<IEncryptionService, AesEncryptionService>();
builder.Services.AddScoped<IJwtService, JwtService>();

// Add session support to store small bits of user data in server memory
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    // Session will expire after 30 minutes of inactivity
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;    // Prevent JavaScript from accessing the session cookie
    options.Cookie.IsEssential = true; // Ensure the session cookie is always sent
});

// Read JWT settings (Key, Issuer, Audience, Expiration) from configuration
var jwtCfg = builder.Configuration.GetSection("Jwt");
var key = Encoding.UTF8.GetBytes(jwtCfg["Key"]);

// Configure authentication to use JWT Bearer tokens
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false; // In production, set this to true to require HTTPS
    options.SaveToken = true;             // Store the token in the AuthenticationProperties
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,                   // Ensure the token is signed with a valid key
        IssuerSigningKey = new SymmetricSecurityKey(key),  // The key used to sign the token
        ValidateIssuer = true,                             // Ensure the token was issued by a trusted issuer
        ValidIssuer = jwtCfg["Issuer"],
        ValidateAudience = true,                           // Ensure the token is intended for our audience
        ValidAudience = jwtCfg["Audience"],
        ValidateLifetime = true,                           // Reject expired tokens
        ClockSkew = TimeSpan.Zero                          // No tolerance for token expiry
    };
});

// Add MVC controllers with views and enable authorization policies
builder.Services.AddControllersWithViews();
builder.Services.AddAuthorization();

var app = builder.Build();

// Serve static files (CSS, JS, images) from wwwroot
app.UseStaticFiles();

// Redirect 401/403 status codes to custom error pages
app.UseStatusCodePages(context =>
{
    var response = context.HttpContext.Response;
    if (response.StatusCode == 401)
    {
        response.Redirect("/Error/Unauthorized");
    }
    else if (response.StatusCode == 403)
    {
        response.Redirect("/Error/Forbidden");
    }
    return Task.CompletedTask;
});

// Enable routing for controllers
app.UseRouting();

// Enable session support before authentication
app.UseSession();

// Inject the JWT from session into the Authorization header on each request
//app.UseMiddleware<JwtHeaderMiddleware>();
app.UseMiddleware<JwtRefreshMiddleware>();

// Authenticate requests and enforce authorization
app.UseAuthentication();
app.UseAuthorization();

// Define the default controller route pattern
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// Start processing incoming HTTP requests
app.Run();
