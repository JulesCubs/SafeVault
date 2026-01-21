using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SafeVault.Data;            // ✅ Necesario para SessionRepository y AuditLogRepository
using SafeVault.Models;

namespace SafeVault.Services
{
    public interface IAuthorizationService
    {
        Task<bool> ValidateSessionAsync(string sessionToken);
        Task<bool> IsUserInRoleAsync(int userId, string roleName);
        Task<bool> HasPermissionAsync(int userId, string requiredRole);
        Task<int?> GetUserIdFromSessionAsync(string sessionToken);
        Task<List<string>> GetUserRolesAsync(int userId);
    }

    public class AuthorizationService : IAuthorizationService
    {
        private readonly SessionRepository _sessionRepository;
        private readonly UserRepository _userRepository;
        private readonly AuditLogRepository _auditRepository;

        public AuthorizationService(
            SessionRepository sessionRepository,
            UserRepository userRepository,
            AuditLogRepository auditRepository = null)
        {
            _sessionRepository = sessionRepository ?? throw new ArgumentNullException(nameof(sessionRepository));
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _auditRepository = auditRepository;
        }

        /// <summary>
        /// Valida que la sesión sea válida y no esté expirada
        /// </summary>
        public async Task<bool> ValidateSessionAsync(string sessionToken)
        {
            if (string.IsNullOrWhiteSpace(sessionToken))
                return false;

            var session = await _sessionRepository.GetSessionByTokenAsync(sessionToken);
            
            if (session == null || !session.IsValid)
                return false;

            // Verificar si la sesión expiró
            if (session.ExpiresAt < DateTime.UtcNow)
            {
                await _sessionRepository.InvalidateSessionAsync(session.SessionID);
                return false;
            }

            return true;
        }

        /// <summary>
        /// Verifica si un usuario tiene un rol específico
        /// </summary>
        public async Task<bool> IsUserInRoleAsync(int userId, string roleName)
        {
            if (userId <= 0 || string.IsNullOrWhiteSpace(roleName))
                return false;

            try
            {
                var roles = await _userRepository.GetUserRolesAsync(userId);
                return roles.Contains(roleName);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error verificando rol: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Verifica si el usuario tiene permiso basado en roles jerárquicos
        /// Jerarquía: Admin > Manager > User > Guest
        /// </summary>
        public async Task<bool> HasPermissionAsync(int userId, string requiredRole)
        {
            if (userId <= 0 || string.IsNullOrWhiteSpace(requiredRole))
                return false;

            try
            {
                var userRoles = await _userRepository.GetUserRolesAsync(userId);
                
                return requiredRole.ToLower() switch
                {
                    "admin" => userRoles.Contains("Admin"),
                    
                    "manager" => userRoles.Contains("Admin") || userRoles.Contains("Manager"),
                    
                    "user" => userRoles.Contains("Admin") || 
                             userRoles.Contains("Manager") || 
                             userRoles.Contains("User"),
                    
                    "guest" => userRoles.Count > 0,
                    
                    _ => false
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error verificando permisos: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Obtiene el ID del usuario desde el token de sesión
        /// </summary>
        public async Task<int?> GetUserIdFromSessionAsync(string sessionToken)
        {
            var session = await _sessionRepository.GetSessionByTokenAsync(sessionToken);
            return session?.UserId;
        }

        /// <summary>
        /// Obtiene los roles de un usuario
        /// </summary>
        public async Task<List<string>> GetUserRolesAsync(int userId)
        {
            if (userId <= 0)
                return new List<string>();

            try
            {
                return await _userRepository.GetUserRolesAsync(userId);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error obteniendo roles: {ex.Message}");
                return new List<string>();
            }
        }
    }
}