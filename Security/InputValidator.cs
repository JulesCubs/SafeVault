using System;
using System.Text.RegularExpressions;

namespace SafeVault.Security
{
    public static class InputValidator
    {
        /// <summary>
        /// Valida el formato del nombre de usuario
        /// </summary>
        public static (bool IsValid, string ErrorMessage) ValidateUsername(string username)
        {
            if (string.IsNullOrWhiteSpace(username))
                return (false, "El nombre de usuario no puede estar vacío");

            if (username.Length < 3)
                return (false, "El nombre de usuario debe tener al menos 3 caracteres");

            if (username.Length > 50)
                return (false, "El nombre de usuario no puede exceder 50 caracteres");

            // Solo letras, números y guiones bajos
            if (!Regex.IsMatch(username, @"^[a-zA-Z0-9_-]+$"))
                return (false, "El nombre de usuario solo puede contener letras, números, guiones y guiones bajos");

            return (true, "Válido");
        }

        /// <summary>
        /// Valida el formato del email
        /// </summary>
        public static (bool IsValid, string ErrorMessage) ValidateEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return (false, "El email no puede estar vacío");

            if (email.Length > 100)
                return (false, "El email no puede exceder 100 caracteres");

            // Expresión regular para validar email
            string pattern = @"^[^@\s]+@[^@\s]+\.[^@\s]+$";
            if (!Regex.IsMatch(email, pattern))
                return (false, "El formato del email no es válido");

            return (true, "Válido");
        }

        /// <summary>
        /// Valida la complejidad de la contraseña
        /// OWASP A07:2021 - Identification and Authentication Failures
        /// </summary>
        public static (bool IsValid, string ErrorMessage) ValidatePasswordComplexity(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                return (false, "La contraseña no puede estar vacía");

            if (password.Length < 8)
                return (false, "La contraseña debe tener al menos 8 caracteres");

            if (password.Length > 128)
                return (false, "La contraseña no puede exceder 128 caracteres");

            // Verificar mayúsculas
            if (!Regex.IsMatch(password, @"[A-Z]"))
                return (false, "La contraseña debe contener al menos una letra mayúscula");

            // Verificar minúsculas
            if (!Regex.IsMatch(password, @"[a-z]"))
                return (false, "La contraseña debe contener al menos una letra minúscula");

            // Verificar números
            if (!Regex.IsMatch(password, @"[0-9]"))
                return (false, "La contraseña debe contener al menos un número");

            // Verificar caracteres especiales
            if (!Regex.IsMatch(password, @"[!@#$%^&*()_+\-=\[\]{};':""\\|,.<>?/`~]"))
                return (false, "La contraseña debe contener al menos un carácter especial (!@#$%^&*)");

            return (true, "Válido");
        }

        /// <summary>
        /// Sanitiza términos de búsqueda para prevenir inyecciones
        /// OWASP A03:2021 - Injection
        /// </summary>
        public static string SanitizeSearchTerm(string searchTerm)
        {
            if (string.IsNullOrWhiteSpace(searchTerm))
                return string.Empty;

            // Remover caracteres especiales peligrosos
            string sanitized = Regex.Replace(searchTerm, @"[^\w\s-]", "");
            
            // Limitar longitud
            return sanitized.Length > 100 ? sanitized.Substring(0, 100) : sanitized;
        }

        /// <summary>
        /// Valida que una cadena no contenga caracteres especiales SQL
        /// OWASP A03:2021 - Injection
        /// </summary>
        public static bool IsSafeSqlString(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return true;

            // Caracteres peligrosos en SQL
            char[] dangerousChars = { ';', '\'', '"', '-', '*', '/', '\\', '\0' };
            
            foreach (char c in dangerousChars)
            {
                if (input.Contains(c))
                    return false;
            }

            return true;
        }
    }
}