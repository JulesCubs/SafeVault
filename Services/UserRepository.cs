using System;
using System.Collections.Generic;
using System.Data;
using Microsoft.Data.SqlClient;
using System.Threading.Tasks;
using SafeVault.Models;

namespace SafeVault.Services
{
    /// <summary>
    /// Repositorio de usuarios con seguridad conforme a OWASP
    /// A01:2021 - Broken Access Control: Validación de acceso
    /// A03:2021 - Injection: Parámetros SQL seguros
    /// A09:2021 - Logging and Monitoring Failures: Auditoría completa
    /// </summary>
    public class UserRepository
    {
        private readonly string _connectionString;

        public UserRepository(string connectionString)
        {
            if (string.IsNullOrWhiteSpace(connectionString))
                throw new ArgumentException("La cadena de conexión no puede estar vacía", nameof(connectionString));
            
            _connectionString = connectionString;
        }

        /// <summary>
        /// Obtiene un usuario por username utilizando sentencias parametrizadas seguras
        /// </summary>
        public async Task<User?> GetUserByUsernameAsync(string username)
        {
            // Validar entrada
            var (isValid, errorMessage) = InputValidator.ValidateUsername(username);
            if (!isValid)
            {
                SecurityAuditLogger.LogUnauthorizedAccessAttempt("GetUserByUsername", $"Nombre de usuario inválido: {errorMessage}");
                throw new ArgumentException(errorMessage);
            }

            const string query = "SELECT Id, Username, Email, PasswordHash, CreatedAt, UpdatedAt, IsActive, " +
                               "FailedLoginAttempts, LastFailedLoginAttempt, LastSuccessfulLogin " +
                               "FROM Users WHERE Username = @Username AND IsActive = 1";

            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        // Parámetros seguros contra SQL Injection
                        command.Parameters.AddWithValue("@Username", username);
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30; // Timeout para evitar DoS

                        using (SqlDataReader reader = await command.ExecuteReaderAsync())
                        {
                            if (await reader.ReadAsync())
                            {
                                return MapReaderToUser(reader);
                            }
                        }
                    }
                }
            }
            catch (SqlException ex)
            {
                SecurityAuditLogger.LogSqlException("GetUserByUsername", ex);
                throw new Exception("Error al recuperar usuario de la base de datos", ex);
            }

            return null;
        }

        /// <summary>
        /// Obtiene un usuario por email utilizando sentencias parametrizadas
        /// </summary>
        public async Task<User?> GetUserByEmailAsync(string email)
        {
            // Validar entrada
            var (isValid, errorMessage) = InputValidator.ValidateEmail(email);
            if (!isValid)
            {
                SecurityAuditLogger.LogUnauthorizedAccessAttempt("GetUserByEmail", $"Email inválido: {errorMessage}");
                throw new ArgumentException(errorMessage);
            }

            const string query = "SELECT Id, Username, Email, PasswordHash, CreatedAt, UpdatedAt, IsActive, " +
                               "FailedLoginAttempts, LastFailedLoginAttempt, LastSuccessfulLogin " +
                               "FROM Users WHERE Email = @Email AND IsActive = 1";

            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();
                    
                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@Email", email);
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;

                        using (SqlDataReader reader = await command.ExecuteReaderAsync())
                        {
                            if (await reader.ReadAsync())
                            {
                                return MapReaderToUser(reader);
                            }
                        }
                    }
                }
            }
            catch (SqlException ex)
            {
                SecurityAuditLogger.LogSqlException("GetUserByEmail", ex);
                throw new Exception("Error al recuperar usuario de la base de datos", ex);
            }

            return null;
        }

        /// <summary>
        /// Busca usuarios por criterio de búsqueda seguro con límites
        /// </summary>
        public async Task<List<User>> SearchUsersAsync(string searchTerm)
        {
            if (string.IsNullOrWhiteSpace(searchTerm))
                throw new ArgumentException("El término de búsqueda no puede estar vacío");

            // Sanitizar entrada para prevenir inyecciones
            string sanitized = InputValidator.SanitizeSearchTerm(searchTerm);

            const string query = "SELECT TOP 100 Id, Username, Email, PasswordHash, CreatedAt, UpdatedAt, IsActive, " +
                               "FailedLoginAttempts, LastFailedLoginAttempt, LastSuccessfulLogin " +
                               "FROM Users WHERE (Username LIKE @SearchTerm OR Email LIKE @SearchTerm) " +
                               "AND IsActive = 1 ORDER BY Username";

            var users = new List<User>();

            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        // Usar LIKE de forma segura con parámetros
                        command.Parameters.AddWithValue("@SearchTerm", $"%{sanitized}%");
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;

                        await connection.OpenAsync();
                        using (SqlDataReader reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                users.Add(MapReaderToUser(reader));
                            }
                        }
                    }
                }
            }
            catch (SqlException ex)
            {
                SecurityAuditLogger.LogSqlException("SearchUsers", ex);
                throw new Exception("Error al buscar usuarios", ex);
            }

            return users;
        }

        /// <summary>
        /// Crea un nuevo usuario con validaciones de seguridad OWASP
        /// </summary>
        public async Task<bool> CreateUserAsync(string username, string email, string passwordHash)
        {
            // Validaciones de entrada conforme a OWASP
            var (isValidUsername, usernameError) = InputValidator.ValidateUsername(username);
            if (!isValidUsername)
                throw new ArgumentException(usernameError);

            var (isValidEmail, emailError) = InputValidator.ValidateEmail(email);
            if (!isValidEmail)
                throw new ArgumentException(emailError);

            if (string.IsNullOrEmpty(passwordHash))
                throw new ArgumentException("El hash de la contraseña no puede estar vacío");

            // Verificar que el usuario no exista
            var existingUser = await GetUserByUsernameAsync(username);
            if (existingUser != null)
                throw new InvalidOperationException("El nombre de usuario ya existe");

            const string query = "INSERT INTO Users (Username, Email, PasswordHash, CreatedAt, UpdatedAt, IsActive, " +
                               "FailedLoginAttempts) VALUES (@Username, @Email, @PasswordHash, @CreatedAt, @UpdatedAt, 1, 0)";

            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@Username", username);
                        command.Parameters.AddWithValue("@Email", email);
                        command.Parameters.AddWithValue("@PasswordHash", passwordHash);
                        command.Parameters.AddWithValue("@CreatedAt", DateTime.UtcNow);
                        command.Parameters.AddWithValue("@UpdatedAt", DateTime.UtcNow);
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;

                        await connection.OpenAsync();
                        int rowsAffected = await command.ExecuteNonQueryAsync();
                        
                        if (rowsAffected > 0)
                        {
                            SecurityAuditLogger.LogUserCreation(username, email);
                            return true;
                        }
                    }
                }
            }
            catch (SqlException ex)
            {
                SecurityAuditLogger.LogSqlException("CreateUser", ex);
                throw new Exception("Error al crear usuario en la base de datos", ex);
            }

            return false;
        }

        /// <summary>
        /// Actualiza la contraseña de un usuario
        /// </summary>
        public async Task<bool> UpdatePasswordAsync(int userId, string newPasswordHash)
        {
            if (userId <= 0 || string.IsNullOrWhiteSpace(newPasswordHash))
                return false;

            const string query = "UPDATE Users SET PasswordHash = @PasswordHash, UpdatedAt = @UpdatedAt WHERE Id = @UserId";

            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();

                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@UserId", userId);
                        command.Parameters.AddWithValue("@PasswordHash", newPasswordHash);
                        command.Parameters.AddWithValue("@UpdatedAt", DateTime.UtcNow);
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;

                        int result = await command.ExecuteNonQueryAsync();
                        return result > 0;
                    }
                }
            }
            catch (SqlException ex)
            {
                Console.WriteLine($"Error actualizando contraseña: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Registra un intento de login fallido
        /// </summary>
        public async Task<bool> RecordFailedLoginAttemptAsync(int userId)
        {
            const string query = "UPDATE Users SET FailedLoginAttempts = FailedLoginAttempts + 1, " +
                               "LastFailedLoginAttempt = @LastAttempt WHERE Id = @UserId";

            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@UserId", userId);
                        command.Parameters.AddWithValue("@LastAttempt", DateTime.UtcNow);
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;

                        await connection.OpenAsync();
                        return await command.ExecuteNonQueryAsync() > 0;
                    }
                }
            }
            catch (SqlException ex)
            {
                SecurityAuditLogger.LogSqlException("RecordFailedLoginAttempt", ex);
                throw;
            }
        }

        /// <summary>
        /// Registra un login exitoso
        /// </summary>
        public async Task<bool> RecordSuccessfulLoginAsync(int userId)
        {
            const string query = "UPDATE Users SET FailedLoginAttempts = 0, LastSuccessfulLogin = @LastLogin " +
                               "WHERE Id = @UserId";

            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@UserId", userId);
                        command.Parameters.AddWithValue("@LastLogin", DateTime.UtcNow);
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;

                        await connection.OpenAsync();
                        return await command.ExecuteNonQueryAsync() > 0;
                    }
                }
            }
            catch (SqlException ex)
            {
                SecurityAuditLogger.LogSqlException("RecordSuccessfulLogin", ex);
                throw;
            }
        }

        /// <summary>
        /// Elimina un usuario (desactivación lógica)
        /// </summary>
        public async Task<bool> DeleteUserAsync(int userId)
        {
            if (userId <= 0)
                throw new ArgumentException("El Id de usuario es inválido");

            const string query = "UPDATE Users SET IsActive = 0, UpdatedAt = @UpdatedAt WHERE Id = @UserId";

            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@UserId", userId);
                        command.Parameters.AddWithValue("@UpdatedAt", DateTime.UtcNow);
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;

                        await connection.OpenAsync();
                        return await command.ExecuteNonQueryAsync() > 0;
                    }
                }
            }
            catch (SqlException ex)
            {
                SecurityAuditLogger.LogSqlException("DeleteUser", ex);
                throw new Exception("Error al eliminar usuario", ex);
            }
        }

        /// <summary>
        /// Resetea el contador de intentos fallidos de login
        /// </summary>
        public async Task<bool> ResetFailedLoginAsync(int userId)
        {
            if (userId <= 0)
                throw new ArgumentException("El Id de usuario es inválido");

            const string query = "UPDATE Users SET FailedLoginAttempts = 0, " +
                               "LastFailedLoginAttempt = NULL, UpdatedAt = @UpdatedAt WHERE Id = @UserId";

            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@UserId", userId);
                        command.Parameters.AddWithValue("@UpdatedAt", DateTime.UtcNow);
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;

                        await connection.OpenAsync();
                        int rowsAffected = await command.ExecuteNonQueryAsync();
                        
                        if (rowsAffected > 0)
                        {
                            SecurityAuditLogger.LogPasswordChange(userId);
                            return true;
                        }
                    }
                }
            }
            catch (SqlException ex)
            {
                SecurityAuditLogger.LogSqlException("ResetFailedLogin", ex);
                throw new Exception("Error al resetear intentos fallidos", ex);
            }

            return false;
        }

        /// <summary>
        /// Actualiza el último login exitoso
        /// </summary>
        public async Task<bool> UpdateLastSuccessfulLoginAsync(int userId)
        {
            if (userId <= 0)
                throw new ArgumentException("El Id de usuario es inválido");

            const string query = "UPDATE Users SET LastSuccessfulLogin = @LastSuccessfulLogin, " +
                               "UpdatedAt = @UpdatedAt WHERE Id = @UserId";

            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@UserId", userId);
                        command.Parameters.AddWithValue("@LastSuccessfulLogin", DateTime.UtcNow);
                        command.Parameters.AddWithValue("@UpdatedAt", DateTime.UtcNow);
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;

                        await connection.OpenAsync();
                        return await command.ExecuteNonQueryAsync() > 0;
                    }
                }
            }
            catch (SqlException ex)
            {
                SecurityAuditLogger.LogSqlException("UpdateLastSuccessfulLogin", ex);
                throw new Exception("Error al actualizar último login", ex);
            }
        }

        /// <summary>
        /// Asigna un rol a un usuario
        /// </summary>
        public async Task<bool> AssignRoleAsync(int userId, string roleName)
        {
            if (userId <= 0)
                throw new ArgumentException("El Id de usuario es inválido");

            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentException("El nombre del rol no puede estar vacío");

            const string getRoleQuery = "SELECT Id FROM Roles WHERE RoleName = @RoleName";
            const string assignRoleQuery = "INSERT INTO UserRoles (UserId, RoleID, AssignedAt) " +
                                          "VALUES (@UserId, @RoleID, @AssignedAt)";

            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();

                    // Obtener el ID del rol
                    int roleId = 0;
                    using (SqlCommand getRoleCommand = new SqlCommand(getRoleQuery, connection))
                    {
                        getRoleCommand.CommandType = CommandType.Text;
                        getRoleCommand.CommandTimeout = 30;
                        getRoleCommand.Parameters.AddWithValue("@RoleName", roleName);

                        var result = await getRoleCommand.ExecuteScalarAsync();
                        if (result != null)
                            roleId = (int)result;
                    }

                    if (roleId == 0)
                        throw new InvalidOperationException($"El rol '{roleName}' no existe");

                    // Asignar el rol al usuario
                    using (SqlCommand assignRoleCommand = new SqlCommand(assignRoleQuery, connection))
                    {
                        assignRoleCommand.CommandType = CommandType.Text;
                        assignRoleCommand.CommandTimeout = 30;
                        assignRoleCommand.Parameters.AddWithValue("@UserId", userId);
                        assignRoleCommand.Parameters.AddWithValue("@RoleID", roleId);
                        assignRoleCommand.Parameters.AddWithValue("@AssignedAt", DateTime.UtcNow);

                        int rowsAffected = await assignRoleCommand.ExecuteNonQueryAsync();
                        return rowsAffected > 0;
                    }
                }
            }
            catch (SqlException ex)
            {
                SecurityAuditLogger.LogSqlException("AssignRole", ex);
                throw new Exception("Error al asignar rol", ex);
            }
        }

        /// <summary>
        /// Obtiene los roles de un usuario
        /// </summary>
        public async Task<List<string>> GetUserRolesAsync(int userId)
        {
            if (userId <= 0)
                throw new ArgumentException("El Id de usuario es inválido");

            const string query = "SELECT r.RoleName FROM UserRoles ur " +
                               "INNER JOIN Roles r ON ur.RoleID = r.Id " +
                               "WHERE ur.UserId = @UserId";

            var roles = new List<string>();

            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;
                        command.Parameters.AddWithValue("@UserId", userId);

                        await connection.OpenAsync();
                        using (SqlDataReader reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                roles.Add(reader.GetString(0));
                            }
                        }
                    }
                }
            }
            catch (SqlException ex)
            {
                SecurityAuditLogger.LogSqlException("GetUserRoles", ex);
                throw new Exception("Error al obtener roles del usuario", ex);
            }

            return roles;
        }

        /// <summary>
        /// Mapea datos del SqlDataReader a un objeto User
        /// </summary>
        private User MapReaderToUser(SqlDataReader reader)
        {
            return new User
            {
                Id = reader.GetInt32(0),
                Username = reader.IsDBNull(1) ? "N/A" : reader.GetString(1),
                Email = reader.IsDBNull(2) ? "N/A" : reader.GetString(2),
                PasswordHash = reader.IsDBNull(3) ? "N/A" : reader.GetString(3),
                CreatedAt = reader.GetDateTime(4),
                UpdatedAt = reader.GetDateTime(5),
                IsActive = reader.GetBoolean(6),
                FailedLoginAttempts = reader.GetInt32(7),
                LastFailedLoginAttempt = reader.IsDBNull(8) ? null : (DateTime?)reader.GetDateTime(8),
                LastSuccessfulLogin = reader.IsDBNull(9) ? null : (DateTime?)reader.GetDateTime(9)
            };
        }

        /// <summary>
        /// Actualiza el contador de intentos fallidos de login
        /// </summary>
        public async Task<bool> UpdateFailedLoginAsync(int userId)
        {
            if (userId <= 0)
                throw new ArgumentException("El Id de usuario es inválido");

            const string query = "UPDATE Users SET FailedLoginAttempts = FailedLoginAttempts + 1, " +
                               "LastFailedLoginAttempt = @LastFailedLoginAttempt, UpdatedAt = @UpdatedAt " +
                               "WHERE Id = @UserId";

            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();

                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@UserId", userId);
                        command.Parameters.AddWithValue("@LastFailedLoginAttempt", DateTime.UtcNow);
                        command.Parameters.AddWithValue("@UpdatedAt", DateTime.UtcNow);
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;

                        int result = await command.ExecuteNonQueryAsync();
                        return result > 0;
                    }
                }
            }
            catch (SqlException ex)
            {
                Console.WriteLine($"Error actualizando intentos fallidos: {ex.Message}");
                return false;
            }
        }
    }
}