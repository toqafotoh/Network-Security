using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace NetworkSecurityApp.Models
{
    public class RefreshToken
    {
        [Key] public int Id { get; set; }
        [Required] public string Token { get; set; }
        public DateTime Expires { get; set; }
        public bool IsRevoked { get; set; }
        [Required] public int UserId { get; set; }
        [ForeignKey(nameof(UserId))] public User User { get; set; }
    }
}