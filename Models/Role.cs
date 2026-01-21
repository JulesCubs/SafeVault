using System;

namespace SafeVault.Models
{
    /// <summary>
    /// Modelo de Role
    /// </summary>
    public class Role
    {
        public int Id { get; set; }
        public string RoleName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public bool IsActive { get; set; }
    }

    /// <summary>
    /// Enum de roles predefinidos
    /// </summary>
    public enum RoleType
    {
        Admin = 1,
        Manager = 2,
        User = 3,
        Guest = 4
    }
}