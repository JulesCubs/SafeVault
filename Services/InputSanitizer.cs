using System;
using System.Text.RegularExpressions;

public class InputSanitizer
{
    /// <summary>
    /// Desinfecta la entrada eliminando caracteres maliciosos
    /// </summary>
    public static string SanitizeInput(string input)
    {
        if (string.IsNullOrEmpty(input))
            return string.Empty;

        // Elimina caracteres de control y scripts potenciales
        string sanitized = Regex.Replace(input, @"[^\w\s@.-]", "");
        
        // Elimina etiquetas HTML/Script
        sanitized = Regex.Replace(sanitized, @"<[^>]*>", "");
        
        // Elimina caracteres de comillas y caracteres especiales SQL
        sanitized = sanitized.Replace("'", "").Replace("\"", "").Replace(";", "");
        
        return sanitized.Trim();
    }

    /// <summary>
    /// Valida el formato del email
    /// </summary>
    public static bool IsValidEmail(string email)
    {
        if (string.IsNullOrEmpty(email))
            return false;

        try
        {
            var addr = new System.Net.Mail.MailAddress(email);
            return addr.Address == email;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Valida el username (solo caracteres alfanuméricos, guiones y guiones bajos)
    /// </summary>
    public static bool IsValidUsername(string username)
    {
        if (string.IsNullOrEmpty(username) || username.Length < 3 || username.Length > 20)
            return false;

        return Regex.IsMatch(username, @"^[a-zA-Z0-9_-]+$");
    }
}