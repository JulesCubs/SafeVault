using System;

namespace SafeVault.Models
{
    /// <summary>
    /// Modelo de Usuario
    /// </summary>
    public class User
    {
        /// <summary>
        /// Identificador único del usuario
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Nombre de usuario único (3-50 caracteres)
        /// </summary>
        public string Username { get; set; } = string.Empty;

        /// <summary>
        /// Email único del usuario
        /// </summary>
        public string Email { get; set; } = string.Empty;

        /// <summary>
        /// Hash PBKDF2 de la contraseña (nunca se almacena la contraseña en texto plano)
        /// </summary>
        public string PasswordHash { get; set; } = string.Empty;

        /// <summary>
        /// Fecha de creación en UTC
        /// </summary>
        public DateTime CreatedAt { get; set; }

        /// <summary>
        /// Fecha de última actualización en UTC
        /// </summary>
        public DateTime UpdatedAt { get; set; }

        /// <summary>
        /// Indica si la cuenta está activa
        /// </summary>
        public bool IsActive { get; set; }

        /// <summary>
        /// Contador de intentos fallidos de login (para protección contra fuerza bruta)
        /// </summary>
        public int FailedLoginAttempts { get; set; }

        /// <summary>
        /// Fecha de último intento fallido de login
        /// </summary>
        public DateTime? LastFailedLoginAttempt { get; set; }

        /// <summary>
        /// Fecha de último login exitoso
        /// </summary>
        public DateTime? LastSuccessfulLogin { get; set; }
    }
}