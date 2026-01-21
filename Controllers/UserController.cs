using Microsoft.AspNetCore.Mvc;
using SafeVault.Security;
using SafeVault.Services;
using System.Threading.Tasks;

namespace SafeVault.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly AuthenticationService _authService;
        private readonly AuthorizationService _authzService;
        private readonly UserRepository _userRepository;

        public UserController(
            AuthenticationService authService,
            AuthorizationService authzService,
            UserRepository userRepository)
        {
            _authService = authService;
            _authzService = authzService;
            _userRepository = userRepository;
        }

        /// <summary>
        /// Obtiene el perfil del usuario autenticado
        /// </summary>
        [HttpGet("profile")]
        public async Task<IActionResult> GetProfile()
        {
            if (!HttpContext.Items.ContainsKey("UserId"))
                return Unauthorized();

            int userId = (int)HttpContext.Items["UserId"];
            var roles = await _authzService.GetUserRolesAsync(userId);

            return Ok(new 
            { 
                userId, 
                roles,
                message = "Perfil del usuario" 
            });
        }

        /// <summary>
        /// Cambiar contraseña del usuario autenticado
        /// </summary>
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            if (!HttpContext.Items.ContainsKey("UserId"))
                return Unauthorized();

            int userId = (int)HttpContext.Items["UserId"];

            var (success, message) = await _authService.ChangePasswordAsync(
                userId, request.Username, request.CurrentPassword, request.NewPassword);

            return success 
                ? Ok(new { success, message })
                : BadRequest(new { success, message });
        }
    }

    public class ChangePasswordRequest
    {
        public string Username { get; set; }
        public string CurrentPassword { get; set; }
        public string NewPassword { get; set; }
    }
}