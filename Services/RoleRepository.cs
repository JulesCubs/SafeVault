using System;
using System.Collections.Generic;
using System.Data;
using Microsoft.Data.SqlClient;
using System.Threading.Tasks;
using SafeVault.Models;

namespace SafeVault.Services
{
    public class RoleRepository
    {
        private readonly string _connectionString;

        public RoleRepository(string connectionString)
        {
            if (string.IsNullOrWhiteSpace(connectionString))
                throw new ArgumentException("La cadena de conexión no puede estar vacía", nameof(connectionString));
            
            _connectionString = connectionString;
        }

        /// <summary>
        /// Obtiene un rol por su nombre
        /// </summary>
        public async Task<Role> GetRoleByNameAsync(string roleName)
        {
            if (string.IsNullOrWhiteSpace(roleName))
                return null;

            const string query = "SELECT Id, RoleName, Description, CreatedAt, IsActive " +
                               "FROM Roles WHERE RoleName = @RoleName AND IsActive = 1";

            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();

                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;
                        command.Parameters.AddWithValue("@RoleName", roleName);

                        using (SqlDataReader reader = await command.ExecuteReaderAsync())
                        {
                            if (await reader.ReadAsync())
                            {
                                return new Role
                                {
                                    Id = reader.GetInt32(0),
                                    RoleName = reader.GetString(1),
                                    Description = reader.IsDBNull(2) ? null : reader.GetString(2),
                                    CreatedAt = reader.GetDateTime(3),
                                    IsActive = reader.GetBoolean(4)
                                };
                            }
                        }
                    }
                }
            }
            catch (SqlException ex)
            {
                Console.WriteLine($"Error obteniendo rol: {ex.Message}");
            }

            return null;
        }

        /// <summary>
        /// Obtiene todos los roles activos
        /// </summary>
        public async Task<List<Role>> GetAllRolesAsync()
        {
            const string query = "SELECT Id, RoleName, Description, CreatedAt, IsActive " +
                               "FROM Roles WHERE IsActive = 1 ORDER BY RoleName";

            var roles = new List<Role>();

            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();

                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;

                        using (SqlDataReader reader = await command.ExecuteReaderAsync())
                        {
                            while (await reader.ReadAsync())
                            {
                                roles.Add(new Role
                                {
                                    Id = reader.GetInt32(0),
                                    RoleName = reader.GetString(1),
                                    Description = reader.IsDBNull(2) ? null : reader.GetString(2),
                                    CreatedAt = reader.GetDateTime(3),
                                    IsActive = reader.GetBoolean(4)
                                });
                            }
                        }
                    }
                }
            }
            catch (SqlException ex)
            {
                Console.WriteLine($"Error obteniendo roles: {ex.Message}");
            }

            return roles;
        }

        /// <summary>
        /// Crea un nuevo rol
        /// </summary>
        public async Task<bool> CreateRoleAsync(string roleName, string description)
        {
            if (string.IsNullOrWhiteSpace(roleName))
                return false;

            const string query = "INSERT INTO Roles (RoleName, Description, CreatedAt, IsActive) " +
                               "VALUES (@RoleName, @Description, @CreatedAt, @IsActive)";

            try
            {
                using (SqlConnection connection = new SqlConnection(_connectionString))
                {
                    await connection.OpenAsync();

                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.CommandType = CommandType.Text;
                        command.CommandTimeout = 30;
                        command.Parameters.AddWithValue("@RoleName", roleName);
                        command.Parameters.AddWithValue("@Description", description ?? (object)DBNull.Value);
                        command.Parameters.AddWithValue("@CreatedAt", DateTime.UtcNow);
                        command.Parameters.AddWithValue("@IsActive", 1);

                        int result = await command.ExecuteNonQueryAsync();
                        return result > 0;
                    }
                }
            }
            catch (SqlException ex)
            {
                Console.WriteLine($"Error creando rol: {ex.Message}");
                return false;
            }
        }
    }
}