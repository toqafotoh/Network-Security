using NetworkSecurityApp.Models;

namespace NetworkSecurityApp.Services
{
    public interface IJwtService
    {
        string GenerateAccessToken(User user);
        RefreshToken GenerateRefreshToken(int userId);
    }
}