using Xunit;
using Moq;
using FluentAssertions;
using System.Collections.Generic;
using System.Threading.Tasks;
using SafeVault.Services;
using SafeVault.Data;

namespace SafeVault.Tests
{
    public class RoleBasedAccessControlTests
    {
        private readonly Mock<SessionRepository> _mockSessionRepository;
        private readonly Mock<UserRepository> _mockUserRepository;
        private readonly AuthorizationService _authzService;

        public RoleBasedAccessControlTests()
        {
            _mockSessionRepository = new Mock<SessionRepository>();
            _mockUserRepository = new Mock<UserRepository>();

            _authzService = new AuthorizationService(
                _mockSessionRepository.Object,
                _mockUserRepository.Object);
        }

        /// <summary>
        /// Escenario: Admin accediendo al panel de administración
        /// </summary>
        [Fact]
        public async Task AdminAccessControl_AdminCanAccessAdminPanel_ShouldSucceed()
        {
            // Arrange
            int adminId = 1;
            var adminRoles = new List<string> { "Admin" };

            _mockUserRepository
                .Setup(x => x.GetUserRolesAsync(adminId))
                .ReturnsAsync(adminRoles);

            // Act
            var hasAccess = await _authzService.HasPermissionAsync(adminId, "admin");

            // Assert
            hasAccess.Should().BeTrue();
        }

        /// <summary>
        /// Escenario: Usuario regular intentando acceder al panel de administración
        /// </summary>
        [Fact]
        public async Task AdminAccessControl_UserCannotAccessAdminPanel_ShouldFail()
        {
            // Arrange
            int userId = 5;
            var userRoles = new List<string> { "User" };

            _mockUserRepository
                .Setup(x => x.GetUserRolesAsync(userId))
                .ReturnsAsync(userRoles);

            // Act
            var hasAccess = await _authzService.HasPermissionAsync(userId, "admin");

            // Assert
            hasAccess.Should().BeFalse();
        }

        /// <summary>
        /// Escenario: Manager accediendo a recursos de Manager
        /// </summary>
        [Fact]
        public async Task ManagerAccessControl_ManagerCanAccessManagerResources_ShouldSucceed()
        {
            // Arrange
            int managerId = 2;
            var managerRoles = new List<string> { "Manager" };

            _mockUserRepository
                .Setup(x => x.GetUserRolesAsync(managerId))
                .ReturnsAsync(managerRoles);

            // Act
            var hasAccess = await _authzService.HasPermissionAsync(managerId, "manager");

            // Assert
            hasAccess.Should().BeTrue();
        }

        /// <summary>
        /// Escenario: User accediendo a recursos de User
        /// </summary>
        [Fact]
        public async Task UserAccessControl_UserCanAccessUserResources_ShouldSucceed()
        {
            // Arrange
            int userId = 5;
            var userRoles = new List<string> { "User" };

            _mockUserRepository
                .Setup(x => x.GetUserRolesAsync(userId))
                .ReturnsAsync(userRoles);

            // Act
            var hasAccess = await _authzService.HasPermissionAsync(userId, "user");

            // Assert
            hasAccess.Should().BeTrue();
        }

        /// <summary>
        /// Escenario: Múltiples roles - Verificar jerarquía
        /// </summary>
        [Fact]
        public async Task MultipleRoles_UserWithMultipleRoles_ShouldHaveCorrectAccessHierarchy()
        {
            // Arrange
            int userId = 3;
            var userRoles = new List<string> { "Admin", "Manager", "User" };

            _mockUserRepository
                .Setup(x => x.GetUserRolesAsync(userId))
                .ReturnsAsync(userRoles);

            // Act & Assert
            (await _authzService.HasPermissionAsync(userId, "admin")).Should().BeTrue();
            (await _authzService.HasPermissionAsync(userId, "manager")).Should().BeTrue();
            (await _authzService.HasPermissionAsync(userId, "user")).Should().BeTrue();
            (await _authzService.HasPermissionAsync(userId, "guest")).Should().BeTrue();
        }

        /// <summary>
        /// Escenario: Guest no puede acceder a User
        /// </summary>
        [Fact]
        public async Task GuestAccessControl_GuestCannotAccessUserResources_ShouldFail()
        {
            // Arrange
            int guestId = 10;
            var guestRoles = new List<string> { "Guest" };

            _mockUserRepository
                .Setup(x => x.GetUserRolesAsync(guestId))
                .ReturnsAsync(guestRoles);

            // Act
            var hasAccess = await _authzService.HasPermissionAsync(guestId, "user");

            // Assert
            hasAccess.Should().BeFalse();
        }

        /// <summary>
        /// Escenario: Usuario sin roles
        /// </summary>
        [Fact]
        public async Task NoRoles_UserWithoutRoles_CannotAccessAnyResource()
        {
            // Arrange
            int userId = 7;
            var emptyRoles = new List<string>();

            _mockUserRepository
                .Setup(x => x.GetUserRolesAsync(userId))
                .ReturnsAsync(emptyRoles);

            // Act & Assert
            (await _authzService.HasPermissionAsync(userId, "admin")).Should().BeFalse();
            (await _authzService.HasPermissionAsync(userId, "manager")).Should().BeFalse();
            (await _authzService.HasPermissionAsync(userId, "user")).Should().BeFalse();
        }

        /// <summary>
        /// Escenario: Verificar roles de usuario específico
        /// </summary>
        [Fact]
        public async Task UserRoles_GetUserRoles_ShouldReturnCorrectRoles()
        {
            // Arrange
            int userId = 2;
            var expectedRoles = new List<string> { "Manager", "User" };

            _mockUserRepository
                .Setup(x => x.GetUserRolesAsync(userId))
                .ReturnsAsync(expectedRoles);

            // Act
            var roles = await _authzService.GetUserRolesAsync(userId);

            // Assert
            roles.Should().HaveCount(2);
            roles.Should().Contain("Manager");
            roles.Should().Contain("User");
        }
    }
}