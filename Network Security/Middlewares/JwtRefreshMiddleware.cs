namespace Network_Security.Middlewares;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using NetworkSecurityApp.Data;
using NetworkSecurityApp.Services;

public class JwtRefreshMiddleware
{
    private readonly RequestDelegate _next;

    public JwtRefreshMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Resolve scoped services from the request
        var db = context.RequestServices.GetRequiredService<ApplicationDbContext>();
        var jwt = context.RequestServices.GetRequiredService<IJwtService>();

        // Retrieve tokens from session
        var accessToken = context.Session.GetString("accessToken");
        var refreshToken = context.Session.GetString("refreshToken");

        if (!string.IsNullOrEmpty(accessToken))
        {
            var handler = new JwtSecurityTokenHandler();
            // Check if the access token is expired
            if (handler.ReadToken(accessToken) is JwtSecurityToken jwtToken
                && jwtToken.ValidTo < DateTime.UtcNow)
            {
                // Access token expired -> refresh internally
                var stored = await db.RefreshTokens
                    .Include(r => r.User).ThenInclude(u => u.Role)
                    .FirstOrDefaultAsync(r =>
                        r.Token == refreshToken &&
                        !r.IsRevoked &&
                        r.Expires > DateTime.UtcNow);

                if (stored != null)
                {
                    var newAccess = jwt.GenerateAccessToken(stored.User);
                    await db.SaveChangesAsync();
                    context.Session.SetString("accessToken", newAccess);
                    context.Session.SetString("refreshToken", stored.Token);
                    accessToken = newAccess;
                }

                else
                {
                    // Invalid or expired refresh token -> clear session
                    context.Session.Clear();
                }
            }

            // Inject the (new or existing) access token into the Authorization header
            context.Request.Headers["Authorization"] = $"Bearer {accessToken}";

            /* This is only for debugging purposes to view the token in DevTools
             Normally, the token is injected into the request headers by the server (middleware),
             so it won't appear in the browser's network tab because it's not sent by the client.

             context.Response.Headers["X-Debug-AccessToken"] = accessToken; 
            */
        }

        // Proceed to the next middleware
        await _next(context);
    }
}
/*
                if (stored != null)
                {
                    stored.IsRevoked = true;
                    var newAccess = jwt.GenerateAccessToken(stored.User);
                    var newRefresh = jwt.GenerateRefreshToken(stored.UserId);
                    db.RefreshTokens.Add(newRefresh);
                    await db.SaveChangesAsync();
                    context.Session.SetString("accessToken", newAccess);
                    context.Session.SetString("refreshToken", newRefresh.Token);
                    accessToken = newAccess;
                }
*/