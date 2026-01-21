using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using SafeVault.Services;

namespace SafeVault.Security
{
    public class AuthenticationMiddleware
    {
        private readonly RequestDelegate _next;

        public AuthenticationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, AuthorizationService authService)
        {
            try
            {
                // Obtener token del header
                var token = context.Request.Headers["Authorization"].ToString()
                    .Replace("Bearer ", "");

                if (!string.IsNullOrWhiteSpace(token))
                {
                    // Validar sesión
                    var isValid = await authService.ValidateSessionAsync(token);
                    if (isValid)
                    {
                        // Obtener ID del usuario
                        var userId = await authService.GetUserIdFromSessionAsync(token);
                        if (userId.HasValue)
                        {
                            context.Items["UserId"] = userId.Value;
                            context.Items["Token"] = token;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error en middleware de autenticación: {ex.Message}");
            }

            await _next(context);
        }
    }
}