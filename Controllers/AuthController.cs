using Microsoft.AspNetCore.Mvc;
using SafeVault.Services;
using System.Threading.Tasks;

namespace SafeVault.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AuthenticationService _authService;

        public AuthController(AuthenticationService authService)
        {
            _authService = authService;
        }

        /// <summary>
        /// Registra un nuevo usuario
        /// </summary>
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var (success, message) = await _authService.RegisterUserAsync(
                request.Username, request.Email, request.Password);

            return success ? Ok(new { success, message }) : BadRequest(new { success, message });
        }

        /// <summary>
        /// Inicia sesión de usuario
        /// </summary>
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            var userAgent = HttpContext.Request.Headers["User-Agent"].ToString();

            var (success, token, message) = await _authService.LoginAsync(
                request.Username, request.Password, ipAddress, userAgent);

            if (!success)
                return Unauthorized(new { success, message });

            return Ok(new { success, token, message });
        }

        /// <summary>
        /// Cierra la sesión del usuario
        /// </summary>
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            var userIdObj = HttpContext.Items["UserId"];
            if (userIdObj == null || !int.TryParse(userIdObj.ToString(), out int userId))
                return Unauthorized(new { message = "No autorizado" });

            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
            await _authService.LogoutAsync(userId, ipAddress);

            return Ok(new { success = true, message = "Sesión cerrada exitosamente" });
        }
    }

    public class RegisterRequest
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }

    public class LoginRequest
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
}