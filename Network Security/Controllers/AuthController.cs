using BCrypt.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using NetworkSecurityApp.Data;
using NetworkSecurityApp.Models;
using NetworkSecurityApp.Services;
using System.Threading.Tasks;

namespace NetworkSecurityApp.Controllers
{
    public class AuthController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly IJwtService _jwt;
        private readonly IEncryptionService _enc;

        public AuthController(ApplicationDbContext db, IJwtService jwt, IEncryptionService enc)
        {
            _db = db;
            _jwt = jwt;
            _enc = enc;
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(string username, string email, string firstName, string lastName, string password, int roleId)
        {
            // Check if username already exists (encrypted)
            if (await _db.Users.AnyAsync(u => u.EncryptedUsername == _enc.Encrypt(username)))
            {
                ViewBag.Error = "Username already exists.";
                return View();
            }

            // Encrypt sensitive data (username, email) before saving
            var encryptedUsername = _enc.Encrypt(username);
            var encryptedEmail = _enc.Encrypt(email);

            // Hash the password before storing
            var passwordHash = BCrypt.Net.BCrypt.HashPassword(password);

            var user = new User
            {
                EncryptedUsername = encryptedUsername,
                EncryptedEmail = encryptedEmail,
                FirstName = firstName, // First name is stored in plain text
                LastName = lastName,   // Last name is stored in plain text
                PasswordHash = passwordHash, // Store hashed password
                RoleId = roleId
            };

            _db.Users.Add(user);
            await _db.SaveChangesAsync();

            return RedirectToAction("Login");
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(string username, string password)
        {
            // Encrypt the username before searching the database
            var encryptedUsername = _enc.Encrypt(username);

            // Search for the user by encrypted username
            var user = await _db.Users.Include(u => u.Role)
                                       .FirstOrDefaultAsync(u => u.EncryptedUsername == encryptedUsername);

            if (user == null || !BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
            {
                ViewBag.Error = "Invalid username or password.";
                return View();
            }

            // Decrypt the username and email
            var decryptedUsername = _enc.Decrypt(user.EncryptedUsername);
            var decryptedEmail = _enc.Decrypt(user.EncryptedEmail);

            // FirstName and LastName were not encrypted, so we use them directly
            var firstName = user.FirstName;
            var lastName = user.LastName;

            // Generate access and refresh tokens
            var accessToken = _jwt.GenerateAccessToken(user);
            var refreshToken = _jwt.GenerateRefreshToken(user.Id);
            _db.RefreshTokens.Add(refreshToken);
            await _db.SaveChangesAsync();

            // Store tokens and user info in session
            HttpContext.Session.SetString("accessToken", accessToken);
            HttpContext.Session.SetString("refreshToken", refreshToken.Token);
            HttpContext.Session.SetString("username", decryptedUsername);
            HttpContext.Session.SetString("email", decryptedEmail);
            HttpContext.Session.SetString("role", user.Role.Name);

            if (user.Role.Name == "Admin")
            {
                return RedirectToAction("Index", "Admin");
            }
            else if (user.Role.Name == "User")
            {
                TempData["Username"] = decryptedUsername;
                TempData["Email"] = decryptedEmail;
                return RedirectToAction("Index", "User");
            }

            return RedirectToAction("Index", "Home");
        }

        [Authorize]
        [HttpPost]
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        public async Task<IActionResult> Refresh([FromBody] string token)
        {
            // Validate the refresh token
            var stored = await _db.RefreshTokens
                .Include(r => r.User).ThenInclude(u => u.Role)
                .FirstOrDefaultAsync(r => r.Token == token);

            if (stored == null || stored.Expires < DateTime.UtcNow || stored.IsRevoked)
            {
                return Unauthorized(new { message = "Invalid refresh token." });
            }

            // Revoke the old token
            stored.IsRevoked = true;
            var accessToken = _jwt.GenerateAccessToken(stored.User);
            var newRefresh = _jwt.GenerateRefreshToken(stored.UserId);

            _db.RefreshTokens.Add(newRefresh);
            await _db.SaveChangesAsync();

            // Return the new tokens in the response
            return Ok(new
            {
                AccessToken = accessToken,
                RefreshToken = newRefresh.Token
            });
        }
    }
}