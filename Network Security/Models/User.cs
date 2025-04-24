using NetworkSecurityApp.Models;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

public class User
{
    [Key]
    public int Id { get; set; }

    // الحقول المشفرة
    [Required]
    public string EncryptedUsername { get; set; }

    [Required]
    public string EncryptedEmail { get; set; }

    public string FirstName { get; set; }

    public string LastName { get; set; }

    [Required]
    public string PasswordHash { get; set; }

    [Required]
    public int RoleId { get; set; }

    [ForeignKey(nameof(RoleId))]
    public Role Role { get; set; }

    public ICollection<RefreshToken> RefreshTokens { get; set; }
}
