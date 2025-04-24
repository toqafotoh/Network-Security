namespace Network_Security.Middlewares;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

public class JwtHeaderMiddleware
{
    private readonly RequestDelegate _next;

    public JwtHeaderMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var token = context.Session.GetString("accessToken");
        if (!string.IsNullOrEmpty(token) &&
            !context.Request.Headers.ContainsKey("Authorization"))
        {
            context.Request.Headers.Append("Authorization", $"Bearer {token}");
        }

        await _next(context);
    }
}
