using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Security;
using BCrypt.Net;
using System.Text.RegularExpressions;

namespace SafeVault.Services
{
    public class AuthenticationService
    {
        private readonly UserRepository _userRepository;
        private readonly SessionRepository _sessionRepository;
        private readonly AuditLogRepository _auditRepository;
        private const int MAX_FAILED_ATTEMPTS = 5;
        private const int LOCKOUT_MINUTES = 15;

        public AuthenticationService(
            UserRepository userRepository,
            SessionRepository sessionRepository = null,
            AuditLogRepository auditRepository = null)
        {
            _userRepository = userRepository;
            _sessionRepository = sessionRepository;
            _auditRepository = auditRepository;
        }

        /// <summary>
        /// Valida las credenciales del usuario comparando contraseña con hash
        /// OWASP A02:2021 - Cryptographic Failures
        /// </summary>
        public async Task<(bool IsValid, User User)> ValidateCredentialsAsync(string username, string password)
        {
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
                return (false, null);

            try
            {
                // Obtener usuario con sentencia parametrizada
                var user = await _userRepository.GetUserByUsernameAsync(username);

                if (user == null || !user.IsActive)
                    return (false, null);

                // Verificar contraseña con hash bcrypt
                bool isPasswordValid = VerifyPassword(password, user.PasswordHash);

                return (isPasswordValid, user);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error validando credenciales: {ex.Message}");
                return (false, null);
            }
        }

        /// <summary>
        /// Registra un nuevo usuario de forma segura
        /// </summary>
        public async Task<(bool Success, string Message)> RegisterUserAsync(
            string username, string email, string password)
        {
            // Validar entradas conforme a OWASP
            var (isValidUsername, usernameMsg) = InputValidator.ValidateUsername(username);
            if (!isValidUsername)
                return (false, usernameMsg);

            var (isValidEmail, emailMsg) = InputValidator.ValidateEmail(email);
            if (!isValidEmail)
                return (false, emailMsg);

            var (isValidPassword, passwordMsg) = ValidatePasswordComplexity(password);
            if (!isValidPassword)
                return (false, passwordMsg);

            try
            {
                // Verificar si el usuario ya existe
                var existingUser = await _userRepository.GetUserByUsernameAsync(username);
                if (existingUser != null)
                    return (false, "El nombre de usuario ya existe");

                // Verificar si el email ya existe
                var existingEmail = await _userRepository.GetUserByEmailAsync(email);
                if (existingEmail != null)
                    return (false, "El email ya está registrado");

                // Hash de la contraseña con bcrypt (workFactor 12 = ~100ms)
                string passwordHash = HashPasswordBcrypt(password);

                // Crear usuario con sentencia parametrizada
                bool created = await _userRepository.CreateUserAsync(username, email, passwordHash);

                if (created)
                {
                    // Registrar en auditoría
                    if (_auditRepository != null)
                    {
                        await _auditRepository.LogActionAsync(
                            0, "USER_REGISTRATION", 
                            $"Nuevo usuario registrado: {username}", null, null);
                    }
                }

                return (created, created ? "Usuario registrado exitosamente" : "Error al registrar usuario");
            }
            catch (Exception ex)
            {
                return (false, $"Error al registrar: {ex.Message}");
            }
        }

        /// <summary>
        /// Login completo con generación de sesión y auditoría
        /// OWASP A07:2021 - Identification and Authentication Failures
        /// </summary>
        public async Task<(bool Success, string Token, string Message)> LoginAsync(
            string username, string password, string ipAddress, string userAgent)
        {
            try
            {
                // Validar credenciales
                var (isValid, user) = await ValidateCredentialsAsync(username, password);

                if (!isValid || user == null)
                {
                    // Obtener usuario para registrar intento fallido
                    var failedUser = await _userRepository.GetUserByUsernameAsync(username);
                    
                    if (failedUser != null)
                    {
                        // Incrementar intentos fallidos
                        await _userRepository.UpdateFailedLoginAsync(failedUser.Id);
                    }

                    // Registrar intento fallido en auditoría
                    if (_auditRepository != null)
                    {
                        await _auditRepository.LogFailedAccessAttemptAsync(
                            username, ipAddress, "LOGIN_FAILED", "Credenciales inválidas");
                    }

                    return (false, null, "Credenciales inválidas");
                }

                // Verificar bloqueo por intentos fallidos
                if (user.FailedLoginAttempts >= MAX_FAILED_ATTEMPTS)
                {
                    var lastFailedAttempt = user.LastFailedLoginAttempt ?? DateTime.MinValue;
                    var timeSinceLastAttempt = DateTime.UtcNow - lastFailedAttempt;
                    
                    if (timeSinceLastAttempt.TotalMinutes < LOCKOUT_MINUTES)
                    {
                        // Registrar intento bloqueado
                        if (_auditRepository != null)
                        {
                            await _auditRepository.LogFailedAccessAttemptAsync(
                                username, ipAddress, "LOGIN_BLOCKED", 
                                $"Cuenta bloqueada. Intentos fallidos: {user.FailedLoginAttempts}");
                        }

                        int minutesRemaining = LOCKOUT_MINUTES - (int)timeSinceLastAttempt.TotalMinutes;
                        return (false, null, $"Cuenta bloqueada temporalmente. Intente en {minutesRemaining} minutos.");
                    }

                    // Resetear intentos fallidos si expiró el bloqueo
                    await _userRepository.ResetFailedLoginAsync(user.Id);
                }

                // Crear sesión si tenemos sessionRepository
                string sessionToken = null;
                if (_sessionRepository != null)
                {
                    sessionToken = GenerateSessionToken();
                    await _sessionRepository.CreateSessionAsync(
                        user.Id, sessionToken, ipAddress, userAgent);
                }

                // Registrar login exitoso en auditoría
                if (_auditRepository != null)
                {
                    await _auditRepository.LogActionAsync(
                        user.Id, "LOGIN_SUCCESS", 
                        $"Inicio de sesión exitoso desde {ipAddress}", ipAddress, userAgent);
                }

                // Actualizar último login y resetear intentos fallidos
                await _userRepository.UpdateLastSuccessfulLoginAsync(user.Id);
                await _userRepository.ResetFailedLoginAsync(user.Id);

                return (true, sessionToken, "Login exitoso");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error en login: {ex.Message}");
                return (false, null, $"Error en login");
            }
        }

        /// <summary>
        /// Cierra la sesión del usuario
        /// </summary>
        public async Task LogoutAsync(int userId, string ipAddress = null)
        {
            try
            {
                if (_sessionRepository != null)
                    await _sessionRepository.InvalidateUserSessionsAsync(userId);

                if (_auditRepository != null)
                    await _auditRepository.LogActionAsync(
                        userId, "LOGOUT", "Cierre de sesión", ipAddress, null);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al cerrar sesión: {ex.Message}");
            }
        }

        /// <summary>
        /// Cambia la contraseña de un usuario
        /// </summary>
        public async Task<(bool Success, string Message)> ChangePasswordAsync(
            int userId, string username, string currentPassword, string newPassword)
        {
            try
            {
                // Obtener usuario por username
                var user = await _userRepository.GetUserByUsernameAsync(username);
                if (user == null)
                    return (false, "Usuario no encontrado");

                if (user.Id != userId)
                    return (false, "Usuario no autorizado");

                // Verificar contraseña actual
                if (!VerifyPassword(currentPassword, user.PasswordHash))
                    return (false, "Contraseña actual incorrecta");

                // Validar nueva contraseña
                var (IsValid, ErrorMessage) = ValidatePasswordComplexity(newPassword);
                if (!IsValid)
                    return (false, ErrorMessage);

                // Verificar que no sea igual a la anterior
                if (VerifyPassword(newPassword, user.PasswordHash))
                    return (false, "La nueva contraseña no puede ser igual a la anterior");

                // Hash de la nueva contraseña
                string newPasswordHash = HashPasswordBcrypt(newPassword);

                // Actualizar contraseña
                bool updated = await _userRepository.UpdatePasswordAsync(userId, newPasswordHash);

                if (updated && _auditRepository != null)
                {
                    await _auditRepository.LogActionAsync(
                        userId, "PASSWORD_CHANGED", "Contraseña actualizada", null, null);
                }

                return (updated, updated ? "Contraseña actualizada exitosamente" : "Error al actualizar contraseña");
            }
            catch (Exception ex)
            {
                return (false, $"Error: {ex.Message}");
            }
        }

        /// <summary>
        /// Genera un token de sesión seguro usando criptografía
        /// </summary>
        private string GenerateSessionToken()
        {
            var randomNumber = new byte[64];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        /// <summary>
        /// Hash seguro de contraseña usando bcrypt
        /// OWASP A02:2021 - Uso de algoritmos aprobados
        /// </summary>
        private string HashPasswordBcrypt(string password)
        {
            try
            {
                // workFactor 12 proporciona balance entre seguridad y rendimiento (~100ms)
                string hash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
                return hash;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al hashear contraseña: {ex.Message}");
                throw new Exception("Error al procesar la contraseña", ex);
            }
        }

        /// <summary>
        /// Verifica la contraseña contra su hash bcrypt
        /// </summary>
        private bool VerifyPassword(string password, string hash)
        {
            try
            {
                // Comparación segura con bcrypt
                return BCrypt.Net.BCrypt.Verify(password, hash);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error verificando contraseña: {ex.Message}");
                return false;
            }
        }

        private static (bool IsValid, string ErrorMessage) ValidatePasswordComplexity(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                return (false, "La contraseña no puede estar vacía");

            if (password.Length < 8)
                return (false, "La contraseña debe tener al menos 8 caracteres");

            if (password.Length > 128)
                return (false, "La contraseña no puede exceder 128 caracteres");

            if (!Regex.IsMatch(password, @"[A-Z]"))
                return (false, "La contraseña debe contener al menos una letra mayúscula");

            if (!Regex.IsMatch(password, @"[a-z]"))
                return (false, "La contraseña debe contener al menos una letra minúscula");

            if (!Regex.IsMatch(password, @"[0-9]"))
                return (false, "La contraseña debe contener al menos un número");

            if (!Regex.IsMatch(password, @"[!@#$%^&*()_+\-=\[\]{};':""\\|,.<>?/`~]"))
                return (false, "La contraseña debe contener al menos un carácter especial");

            return (true, "Válido");
        }
    }
}