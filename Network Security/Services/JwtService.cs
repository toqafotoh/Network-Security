using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using NetworkSecurityApp.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace NetworkSecurityApp.Services
{
    public class JwtService : IJwtService
    {
        private readonly IConfiguration _config;

        public JwtService(IConfiguration config) => _config = config;

        // Generates a JWT Access Token based on user information
        public string GenerateAccessToken(User user)
        {
            // Ensure the encrypted username exists before creating the token
            if (string.IsNullOrEmpty(user.EncryptedUsername))
            {
                throw new ArgumentException("Username cannot be null or empty");
            }

            // Read JWT settings from configuration
            var jwtCfg = _config.GetSection("Jwt");

            // Create the symmetric key for signing the token
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtCfg["Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // Define the claims to be included in the token
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.EncryptedUsername), // Unique identifier (usually username)
                new Claim(ClaimTypes.Role, user.Role.Name),                     // Role claim (used for authorization)
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Unique token ID to ensure token uniqueness
                new Claim("role", user.Role.Name),                              // Custom claim for role (duplicate for clarity or compatibility)
                new Claim("uid", user.Id.ToString())                            // Custom claim for user ID
            };

            // Create the JWT token
            var token = new JwtSecurityToken(
                issuer: jwtCfg["Issuer"],
                audience: jwtCfg["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(double.Parse(jwtCfg["AccessTokenExpirationMinutes"])), // Token expiration
                signingCredentials: creds
            );

            // Serialize the token to a string and return it
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        // Generates a secure random Refresh Token for the user
        public RefreshToken GenerateRefreshToken(int userId)
        {
            var jwtCfg = _config.GetSection("Jwt");

            var rt = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)), // Secure 64-byte random string
                Expires = DateTime.UtcNow.AddDays(double.Parse(jwtCfg["RefreshTokenExpirationDays"])), // Expiration date from config
                UserId = userId,            // Associate the token with the specific user
                IsRevoked = false           // New token is valid by default
            };

            return rt;
        }
    }
}
