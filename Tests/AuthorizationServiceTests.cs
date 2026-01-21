using Xunit;
using Moq;
using FluentAssertions;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using SafeVault.Services;
using SafeVault.Data;

namespace SafeVault.Tests
{
    public class AuthorizationServiceTests
    {
        private readonly Mock<SessionRepository> _mockSessionRepository;
        private readonly Mock<UserRepository> _mockUserRepository;
        private readonly Mock<AuditLogRepository> _mockAuditRepository;
        private readonly AuthorizationService _authzService;

        public AuthorizationServiceTests()
        {
            _mockSessionRepository = new Mock<SessionRepository>();
            _mockUserRepository = new Mock<UserRepository>();
            _mockAuditRepository = new Mock<AuditLogRepository>();

            _authzService = new AuthorizationService(
                _mockSessionRepository.Object,
                _mockUserRepository.Object,
                _mockAuditRepository.Object);
        }

        #region ValidateSession Tests

        [Fact]
        public async Task ValidateSessionAsync_WithValidSession_ShouldReturnTrue()
        {
            // Arrange
            string token = "valid-token-123";
            var session = new SafeVault.Data.Session
            {
                SessionID = 1,
                UserId = 1,
                SessionToken = token,
                IsValid = true,
                ExpiresAt = DateTime.UtcNow.AddHours(1)
            };

            _mockSessionRepository
                .Setup(x => x.GetSessionByTokenAsync(token))
                .ReturnsAsync(session);

            // Act
            var result = await _authzService.ValidateSessionAsync(token);

            // Assert
            result.Should().BeTrue();
        }

        [Fact]
        public async Task ValidateSessionAsync_WithExpiredSession_ShouldReturnFalse()
        {
            // Arrange
            string token = "expired-token";
            var session = new SafeVault.Data.Session
            {
                SessionID = 1,
                UserId = 1,
                SessionToken = token,
                IsValid = true,
                ExpiresAt = DateTime.UtcNow.AddHours(-1)  // ✅ Expirada
            };

            _mockSessionRepository
                .Setup(x => x.GetSessionByTokenAsync(token))
                .ReturnsAsync(session);

            _mockSessionRepository
                .Setup(x => x.InvalidateSessionAsync(It.IsAny<int>()))
                .ReturnsAsync(true);

            // Act
            var result = await _authzService.ValidateSessionAsync(token);

            // Assert
            result.Should().BeFalse();
            _mockSessionRepository.Verify(x => x.InvalidateSessionAsync(1), Times.Once);
        }

        [Fact]
        public async Task ValidateSessionAsync_WithInvalidSession_ShouldReturnFalse()
        {
            // Arrange
            string token = "invalid-token";
            var session = new SafeVault.Data.Session
            {
                SessionID = 1,
                IsValid = false  // ✅ Sesión inválida
            };

            _mockSessionRepository
                .Setup(x => x.GetSessionByTokenAsync(token))
                .ReturnsAsync(session);

            // Act
            var result = await _authzService.ValidateSessionAsync(token);

            // Assert
            result.Should().BeFalse();
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        public async Task ValidateSessionAsync_WithEmptyToken_ShouldReturnFalse(string token)
        {
            // Act
            var result = await _authzService.ValidateSessionAsync(token);

            // Assert
            result.Should().BeFalse();
        }

        #endregion

        #region Role-Based Authorization Tests

        [Fact]
        public async Task IsUserInRoleAsync_WithValidRole_ShouldReturnTrue()
        {
            // Arrange
            int userId = 1;
            string roleName = "Admin";
            var userRoles = new List<string> { "Admin", "Manager" };

            _mockUserRepository
                .Setup(x => x.GetUserRolesAsync(userId))
                .ReturnsAsync(userRoles);

            // Act
            var result = await _authzService.IsUserInRoleAsync(userId, roleName);

            // Assert
            result.Should().BeTrue();
        }

        [Fact]
        public async Task IsUserInRoleAsync_WithInvalidRole_ShouldReturnFalse()
        {
            // Arrange
            int userId = 1;
            string roleName = "SuperAdmin";  // Rol que no tiene
            var userRoles = new List<string> { "User" };

            _mockUserRepository
                .Setup(x => x.GetUserRolesAsync(userId))
                .ReturnsAsync(userRoles);

            // Act
            var result = await _authzService.IsUserInRoleAsync(userId, roleName);

            // Assert
            result.Should().BeFalse();
        }

        #endregion

        #region Hierarchical Permission Tests

        [Theory]
        [InlineData("Admin", new[] { "Admin" }, true)]
        [InlineData("Admin", new[] { "Manager" }, false)]
        [InlineData("Manager", new[] { "Admin" }, true)]  // Admin tiene acceso a Manager
        [InlineData("Manager", new[] { "Admin", "Manager" }, true)]
        [InlineData("User", new[] { "Admin" }, true)]  // Admin > Manager > User
        [InlineData("User", new[] { "Manager" }, true)]
        [InlineData("User", new[] { "User" }, true)]
        [InlineData("User", new[] { "Guest" }, false)]
        [InlineData("Guest", new[] { "User" }, false)]  // Guest no puede acceder a User
        public async Task HasPermissionAsync_WithHierarchicalRoles_ShouldReturnExpectedResult(
            string requiredRole, string[] userRoles, bool expected)
        {
            // Arrange
            int userId = 1;

            _mockUserRepository
                .Setup(x => x.GetUserRolesAsync(userId))
                .ReturnsAsync(new List<string>(userRoles));

            // Act
            var result = await _authzService.HasPermissionAsync(userId, requiredRole);

            // Assert
            result.Should().Be(expected);
        }

        [Fact]
        public async Task HasPermissionAsync_AdminCanAccessAdminArea_ShouldReturnTrue()
        {
            // Arrange
            int userId = 1;
            var userRoles = new List<string> { "Admin" };

            _mockUserRepository
                .Setup(x => x.GetUserRolesAsync(userId))
                .ReturnsAsync(userRoles);

            // Act
            var result = await _authzService.HasPermissionAsync(userId, "admin");

            // Assert
            result.Should().BeTrue();
        }

        [Fact]
        public async Task HasPermissionAsync_UserCannotAccessAdminArea_ShouldReturnFalse()
        {
            // Arrange
            int userId = 1;
            var userRoles = new List<string> { "User" };

            _mockUserRepository
                .Setup(x => x.GetUserRolesAsync(userId))
                .ReturnsAsync(userRoles);

            // Act
            var result = await _authzService.HasPermissionAsync(userId, "admin");

            // Assert
            result.Should().BeFalse();
        }

        [Fact]
        public async Task HasPermissionAsync_ManagerCanAccessManagerArea_ShouldReturnTrue()
        {
            // Arrange
            int userId = 2;
            var userRoles = new List<string> { "Manager" };

            _mockUserRepository
                .Setup(x => x.GetUserRolesAsync(userId))
                .ReturnsAsync(userRoles);

            // Act
            var result = await _authzService.HasPermissionAsync(userId, "manager");

            // Assert
            result.Should().BeTrue();
        }

        #endregion

        #region GetUserRoles Tests

        [Fact]
        public async Task GetUserRolesAsync_WithValidUser_ShouldReturnRoles()
        {
            // Arrange
            int userId = 1;
            var expectedRoles = new List<string> { "Admin", "Manager" };

            _mockUserRepository
                .Setup(x => x.GetUserRolesAsync(userId))
                .ReturnsAsync(expectedRoles);

            // Act
            var roles = await _authzService.GetUserRolesAsync(userId);

            // Assert
            roles.Should().NotBeEmpty();
            roles.Should().HaveCount(2);
            roles.Should().Contain("Admin");
            roles.Should().Contain("Manager");
        }

        [Fact]
        public async Task GetUserRolesAsync_WithUserWithoutRoles_ShouldReturnEmptyList()
        {
            // Arrange
            int userId = 3;
            var emptyRoles = new List<string>();

            _mockUserRepository
                .Setup(x => x.GetUserRolesAsync(userId))
                .ReturnsAsync(emptyRoles);

            // Act
            var roles = await _authzService.GetUserRolesAsync(userId);

            // Assert
            roles.Should().BeEmpty();
        }

        #endregion

        #region GetUserIdFromSession Tests

        [Fact]
        public async Task GetUserIdFromSessionAsync_WithValidSession_ShouldReturnUserId()
        {
            // Arrange
            string token = "valid-token";
            int expectedUserId = 5;
            var session = new SafeVault.Data.Session { UserId = expectedUserId };

            _mockSessionRepository
                .Setup(x => x.GetSessionByTokenAsync(token))
                .ReturnsAsync(session);

            // Act
            var userId = await _authzService.GetUserIdFromSessionAsync(token);

            // Assert
            userId.Should().Be(expectedUserId);
        }

        [Fact]
        public async Task GetUserIdFromSessionAsync_WithInvalidSession_ShouldReturnNull()
        {
            // Arrange
            string token = "invalid-token";

            _mockSessionRepository
                .Setup(x => x.GetSessionByTokenAsync(token))
                .ReturnsAsync((SafeVault.Data.Session)null);

            // Act
            var userId = await _authzService.GetUserIdFromSessionAsync(token);

            // Assert
            userId.Should().BeNull();
        }

        #endregion
    }
}