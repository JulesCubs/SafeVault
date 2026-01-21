using System;
using System.Data;
using Microsoft.Data.SqlClient;

namespace SafeVault.Security
{
    public static class SecurityAuditLogger
    {
        private static readonly string _connectionString = GetConnectionString();

        private static string GetConnectionString()
        {
            // Obtener desde configuración
            return System.Environment.GetEnvironmentVariable("SAFEVAULT_CONNECTION_STRING") 
                ?? "Server=localhost;Database=SafeVault;Trusted_Connection=true;";
        }

        /// <summary>
        /// Registra intentos de acceso no autorizados
        /// </summary>
        public static void LogUnauthorizedAccessAttempt(string operation, string details)
        {
            LogToAudit("UNAUTHORIZED_ACCESS", operation, details);
        }

        /// <summary>
        /// Registra excepciones SQL
        /// </summary>
        public static void LogSqlException(string operation, SqlException ex)
        {
            LogToAudit("SQL_ERROR", operation, $"SQL Error: {ex.Message} - Number: {ex.Number}");
        }

        /// <summary>
        /// Registra creación de usuario
        /// </summary>
        public static void LogUserCreation(string username, string email)
        {
            LogToAudit("USER_CREATED", username, $"Nuevo usuario creado: {email}");
        }

        /// <summary>
        /// Registra cambio de contraseña
        /// </summary>
        public static void LogPasswordChange(int userId)
        {
            LogToAudit("PASSWORD_CHANGED", userId.ToString(), "Contraseña actualizada");
        }

        /// <summary>
        /// Registra evento en la auditoría
        /// </summary>
        private static void LogToAudit(string eventType, string subject, string details)
        {
            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    connection.Open();

                    string query = @"
                        INSERT INTO AuditLog (EventType, Subject, Details, Timestamp)
                        VALUES (@EventType, @Subject, @Details, @Timestamp)";

                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.Parameters.AddWithValue("@EventType", eventType);
                        command.Parameters.AddWithValue("@Subject", subject ?? "N/A");
                        command.Parameters.AddWithValue("@Details", details ?? "N/A");
                        command.Parameters.AddWithValue("@Timestamp", DateTime.UtcNow);

                        command.ExecuteNonQuery();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error registrando auditoría: {ex.Message}");
            }
        }
    }
}