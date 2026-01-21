using Microsoft.AspNetCore.Mvc;
using SafeVault.Security;
using SafeVault.Services;
using System.Threading.Tasks;

namespace SafeVault.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AdminController : ControllerBase
    {
        private readonly UserRepository _userRepository;
        private readonly RoleRepository _roleRepository;
        private readonly AuthorizationService _authService;

        public AdminController(
            UserRepository userRepository,
            RoleRepository roleRepository,
            AuthorizationService authService)
        {
            _userRepository = userRepository;
            _roleRepository = roleRepository;
            _authService = authService;
        }

        /// <summary>
        /// Obtiene todos los usuarios (solo Admin)
        /// </summary>
        [HttpGet("users")]
        public async Task<IActionResult> GetAllUsers()
        {
            if (!HttpContext.Items.ContainsKey("UserId"))
                return Unauthorized(new { message = "No autorizado" });

            // Verificar que sea Admin
            int userId = (int)HttpContext.Items["UserId"];
            var hasPermission = await _authService.HasPermissionAsync(userId, "admin");
            
            if (!hasPermission)
                return Forbid("No tiene permiso para acceder a este recurso");

            return Ok(new { message = "Lista de usuarios (solo Admin)" });
        }

        /// <summary>
        /// Asigna un rol a un usuario
        /// </summary>
        [HttpPost("users/{userId}/roles")]
        public async Task<IActionResult> AssignRoleToUser(int userId, [FromBody] AssignRoleRequest request)
        {
            if (!HttpContext.Items.ContainsKey("UserId"))
                return Unauthorized();

            int adminId = (int)HttpContext.Items["UserId"];
            var hasPermission = await _authService.HasPermissionAsync(adminId, "admin");
            
            if (!hasPermission)
                return Forbid();

            if (string.IsNullOrWhiteSpace(request.RoleName))
                return BadRequest(new { message = "El nombre del rol es requerido" });

            // Asignar rol
            bool assigned = await _userRepository.AssignRoleAsync(userId, request.RoleName);

            return assigned 
                ? Ok(new { success = true, message = $"Rol '{request.RoleName}' asignado correctamente" })
                : BadRequest(new { success = false, message = "Error al asignar rol" });
        }

        /// <summary>
        /// Obtiene los roles de un usuario
        /// </summary>
        [HttpGet("users/{userId}/roles")]
        public async Task<IActionResult> GetUserRoles(int userId)
        {
            if (!HttpContext.Items.ContainsKey("UserId"))
                return Unauthorized();

            int adminId = (int)HttpContext.Items["UserId"];
            var hasPermission = await _authService.HasPermissionAsync(adminId, "admin");
            
            if (!hasPermission)
                return Forbid();

            var roles = await _userRepository.GetUserRolesAsync(userId);
            return Ok(new { userId, roles });
        }

        /// <summary>
        /// Obtiene todos los roles disponibles
        /// </summary>
        [HttpGet("roles")]
        public async Task<IActionResult> GetAllRoles()
        {
            if (!HttpContext.Items.ContainsKey("UserId"))
                return Unauthorized();

            int adminId = (int)HttpContext.Items["UserId"];
            var hasPermission = await _authService.HasPermissionAsync(adminId, "admin");
            
            if (!hasPermission)
                return Forbid();

            var roles = await _roleRepository.GetAllRolesAsync();
            return Ok(roles);
        }
    }

    public class AssignRoleRequest
    {
        public string RoleName { get; set; }
    }
}