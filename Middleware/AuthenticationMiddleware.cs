using Microsoft.AspNetCore.Http;
using SafeVault.Services;
using System.Threading.Tasks;

namespace SafeVault.Middleware
{
    public class AuthenticationMiddleware
    {
        private readonly RequestDelegate _next;

        public AuthenticationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, IAuthorizationService authService)
        {
            var token = context.Request.Headers["Authorization"].ToString()
                .Replace("Bearer ", "");

            if (!string.IsNullOrEmpty(token))
            {
                if (await authService.ValidateSessionAsync(token))
                {
                    var userId = await authService.GetUserIdFromSessionAsync(token);
                    context.Items["UserId"] = userId;
                    context.Items["SessionToken"] = token;
                }
            }

            await _next(context);
        }
    }
}