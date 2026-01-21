using System;
using System.Data;
using Microsoft.Data.SqlClient;
using System.Threading.Tasks;

namespace SafeVault.Data
{
    public class SessionRepository
    {
        private readonly string _connectionString;

        public SessionRepository(string connectionString)
        {
            if (string.IsNullOrWhiteSpace(connectionString))
                throw new ArgumentException("La cadena de conexión no puede estar vacía", nameof(connectionString));
            
            _connectionString = connectionString;
        }

        /// <summary>
        /// Crea una nueva sesión en la base de datos
        /// </summary>
        public async Task<bool> CreateSessionAsync(int userId, string sessionToken, string ipAddress, string userAgent)
        {
            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();

                    string query = @"
                        INSERT INTO Sessions (UserId, SessionToken, IPAddress, UserAgent, CreatedAt, ExpiresAt, IsValid)
                        VALUES (@UserId, @SessionToken, @IPAddress, @UserAgent, @CreatedAt, @ExpiresAt, @IsValid)";

                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;
                        command.Parameters.AddWithValue("@UserId", userId);
                        command.Parameters.AddWithValue("@SessionToken", sessionToken);
                        command.Parameters.AddWithValue("@IPAddress", ipAddress ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@UserAgent", userAgent ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@CreatedAt", DateTime.UtcNow);
                        command.Parameters.AddWithValue("@ExpiresAt", DateTime.UtcNow.AddHours(1));
                        command.Parameters.AddWithValue("@IsValid", 1);

                        int result = await command.ExecuteNonQueryAsync();
                        return result > 0;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error creando sesión: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Obtiene una sesión por su token
        /// </summary>
        public async Task<Session> GetSessionByTokenAsync(string sessionToken)
        {
            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();

                    string query = @"
                        SELECT SessionID, UserId, SessionToken, IPAddress, UserAgent, 
                               CreatedAt, ExpiresAt, IsValid
                        FROM Sessions
                        WHERE SessionToken = @SessionToken";

                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;
                        command.Parameters.AddWithValue("@SessionToken", sessionToken);

                        using (SqlDataReader reader = await command.ExecuteReaderAsync())
                        {
                            if (await reader.ReadAsync())
                            {
                                return new Session
                                {
                                    SessionID = reader.GetInt32(0),
                                    UserId = reader.GetInt32(1),
                                    SessionToken = reader.GetString(2),
                                    IPAddress = reader.IsDBNull(3) ? null : reader.GetString(3),
                                    UserAgent = reader.IsDBNull(4) ? null : reader.GetString(4),
                                    CreatedAt = reader.GetDateTime(5),
                                    ExpiresAt = reader.GetDateTime(6),
                                    IsValid = reader.GetBoolean(7)
                                };
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error obteniendo sesión: {ex.Message}");
            }

            return null;
        }

        /// <summary>
        /// Invalida todas las sesiones de un usuario
        /// </summary>
        public async Task<bool> InvalidateUserSessionsAsync(int userId)
        {
            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();

                    string query = @"
                        UPDATE Sessions
                        SET IsValid = 0
                        WHERE UserId = @UserId AND IsValid = 1";

                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;
                        command.Parameters.AddWithValue("@UserId", userId);

                        int result = await command.ExecuteNonQueryAsync();
                        return result > 0;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error invalidando sesiones: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Invalida una sesión específica
        /// </summary>
        public async Task<bool> InvalidateSessionAsync(int sessionId)
        {
            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();

                    string query = @"
                        UPDATE Sessions
                        SET IsValid = 0
                        WHERE SessionID = @SessionID";

                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;
                        command.Parameters.AddWithValue("@SessionID", sessionId);

                        int result = await command.ExecuteNonQueryAsync();
                        return result > 0;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error invalidando sesión: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Limpia sesiones expiradas
        /// </summary>
        public async Task<bool> CleanExpiredSessionsAsync()
        {
            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();

                    string query = @"
                        DELETE FROM Sessions
                        WHERE ExpiresAt < GETUTCDATE() OR IsValid = 0";

                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;
                        int result = await command.ExecuteNonQueryAsync();
                        return result > 0;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error limpiando sesiones expiradas: {ex.Message}");
                return false;
            }
        }
    }

    /// <summary>
    /// Modelo de Session
    /// </summary>
    public class Session
    {
        public int SessionID { get; set; }
        public int UserId { get; set; }
        public string SessionToken { get; set; } = string.Empty;
        public string IPAddress { get; set; } = string.Empty;
        public string UserAgent { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public bool IsValid { get; set; }
    }
}