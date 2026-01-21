using System;
using System.Collections.Generic;
using System.Data;
using Microsoft.Data.SqlClient;
using System.Threading.Tasks;

namespace SafeVault.Data
{
    public class AuditLogRepository
    {
        private readonly string _connectionString;

        public AuditLogRepository(string connectionString)
        {
            if (string.IsNullOrWhiteSpace(connectionString))
                throw new ArgumentException("La cadena de conexión no puede estar vacía", nameof(connectionString));
            
            _connectionString = connectionString;
        }

        /// <summary>
        /// Registra una acción en el log de auditoría
        /// </summary>
        public async Task<bool> LogActionAsync(int userId, string action, string details, 
            string ipAddress, string userAgent)
        {
            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();

                    string query = @"
                        INSERT INTO AuditLog (UserId, Action, Details, IPAddress, UserAgent, Timestamp)
                        VALUES (@UserId, @Action, @Details, @IPAddress, @UserAgent, @Timestamp)";

                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;
                        command.Parameters.AddWithValue("@UserId", userId);
                        command.Parameters.AddWithValue("@Action", action);
                        command.Parameters.AddWithValue("@Details", details ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@IPAddress", ipAddress ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@UserAgent", userAgent ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@Timestamp", DateTime.UtcNow);

                        int result = await command.ExecuteNonQueryAsync();
                        return result > 0;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error registrando acción en auditoría: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Registra un intento de acceso fallido
        /// </summary>
        public async Task<bool> LogFailedAccessAttemptAsync(string username, string ipAddress, 
            string attemptType, string details)
        {
            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();

                    string query = @"
                        INSERT INTO FailedAccessAttempts (Username, IPAddress, AttemptType, Details, Timestamp)
                        VALUES (@Username, @IPAddress, @AttemptType, @Details, @Timestamp)";

                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;
                        command.Parameters.AddWithValue("@Username", username ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@IPAddress", ipAddress ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@AttemptType", attemptType);
                        command.Parameters.AddWithValue("@Details", details ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@Timestamp", DateTime.UtcNow);

                        int result = await command.ExecuteNonQueryAsync();
                        return result > 0;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error registrando intento fallido: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Obtiene el historial de auditoría de un usuario
        /// </summary>
        public async Task<List<AuditLog>> GetUserAuditHistoryAsync(int userId, int days = 30)
        {
            List<AuditLog> auditLogs = new List<AuditLog>();

            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();

                    string query = @"
                        SELECT AuditID, UserId, Action, Details, IPAddress, UserAgent, Timestamp
                        FROM AuditLog
                        WHERE UserId = @UserId AND Timestamp >= DATEADD(DAY, -@Days, GETUTCDATE())
                        ORDER BY Timestamp DESC";

                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;
                        command.Parameters.AddWithValue("@UserId", userId);
                        command.Parameters.AddWithValue("@Days", days);

                        using (SqlDataReader reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                auditLogs.Add(new AuditLog
                                {
                                    AuditID = reader.GetInt32(0),
                                    UserId = reader.GetInt32(1),
                                    Action = reader.GetString(2),
                                    Details = reader.IsDBNull(3) ? null : reader.GetString(3),
                                    IPAddress = reader.IsDBNull(4) ? null : reader.GetString(4),
                                    UserAgent = reader.IsDBNull(5) ? null : reader.GetString(5),
                                    Timestamp = reader.GetDateTime(6)
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error obteniendo historial de auditoría: {ex.Message}");
            }

            return auditLogs;
        }

        /// <summary>
        /// Obtiene intentos de acceso fallidos por IP
        /// </summary>
        public async Task<List<FailedAccessAttempt>> GetFailedAttemptsAsync(string ipAddress, int hours = 24)
        {
            List<FailedAccessAttempt> attempts = new List<FailedAccessAttempt>();

            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();

                    string query = @"
                        SELECT AttemptID, Username, IPAddress, AttemptType, Details, Timestamp
                        FROM FailedAccessAttempts
                        WHERE IPAddress = @IPAddress AND Timestamp >= DATEADD(HOUR, -@Hours, GETUTCDATE())
                        ORDER BY Timestamp DESC";

                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;
                        command.Parameters.AddWithValue("@IPAddress", ipAddress);
                        command.Parameters.AddWithValue("@Hours", hours);

                        using (SqlDataReader reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                attempts.Add(new FailedAccessAttempt
                                {
                                    AttemptID = reader.GetInt32(0),
                                    Username = reader.IsDBNull(1) ? null : reader.GetString(1),
                                    IPAddress = reader.IsDBNull(2) ? null : reader.GetString(2),
                                    AttemptType = reader.GetString(3),
                                    Details = reader.IsDBNull(4) ? null : reader.GetString(4),
                                    Timestamp = reader.GetDateTime(5)
                                });
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error obteniendo intentos fallidos: {ex.Message}");
            }

            return attempts;
        }
    }

    /// <summary>
    /// Modelo de AuditLog
    /// </summary>
    public class AuditLog
    {
        public int AuditID { get; set; }
        public int UserId { get; set; }
        public string Action { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
        public string IPAddress { get; set; } = string.Empty;
        public string UserAgent { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
    }

    /// <summary>
    /// Modelo de FailedAccessAttempt
    /// </summary>
    public class FailedAccessAttempt
    {
        public int AttemptID { get; set; }
        public string Username { get; set; } = string.Empty;
        public string IPAddress { get; set; } = string.Empty;
        public string AttemptType { get; set; } = string.Empty;
        public string Details { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
    }
}