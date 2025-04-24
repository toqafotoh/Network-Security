using System;
using System.Linq;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace NetworkSecurityApp.Controllers
{
    public class TokenTestController : Controller
    {
        [Authorize]
        [HttpGet]
        public IActionResult Test()
        {
            // 1) Get the Access Token from the Authorization header
            string bearer = Request.Headers["Authorization"].FirstOrDefault();
            string accessToken = null;
            if (!string.IsNullOrEmpty(bearer) && bearer.StartsWith("Bearer "))
            {
                accessToken = bearer.Substring("Bearer ".Length).Trim();
            }

            // 2) Get the Refresh Token from the Session (as stored after login)
            var refreshToken = HttpContext.Session.GetString("refreshToken");

            // 3) Extract claims from the user principal
            var uidClaim = User.FindFirst("uid")?.Value;
            var roleClaim = User.FindFirst(ClaimTypes.Role)?.Value;
            var expClaim = User.FindFirst(JwtRegisteredClaimNames.Exp)?.Value;

            DateTimeOffset? expiresAt = null;
            if (long.TryParse(expClaim, out var seconds))
                expiresAt = DateTimeOffset.FromUnixTimeSeconds(seconds);

            // 4) Return all the token-related information as JSON
            return Json(new
            {
                Message = "Token is valid!",
                UserId = uidClaim,
                Role = roleClaim,
                ExpiresAt = expiresAt?.ToString("u") ?? "unknown",
                AccessToken = accessToken,
                RefreshToken = refreshToken
            });
        }
    }
}