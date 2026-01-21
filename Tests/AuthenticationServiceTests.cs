using Xunit;
using Moq;
using FluentAssertions;
using System.Threading.Tasks;
using SafeVault.Services;
using SafeVault.Models;
using SafeVault.Data;      // ✅ falta este using para SessionRepository y AuditLogRepository
using BCrypt.Net;

namespace SafeVault.Tests
{
    public class AuthenticationServiceTests
    {
        private readonly Mock<UserRepository> _mockUserRepository;
        private readonly Mock<SessionRepository> _mockSessionRepository;
        private readonly Mock<AuditLogRepository> _mockAuditRepository;
        private readonly AuthenticationService _authService;

        public AuthenticationServiceTests()
        {
            _mockUserRepository = new Mock<UserRepository>();
            _mockSessionRepository = new Mock<SessionRepository>();
            _mockAuditRepository = new Mock<AuditLogRepository>();

            _authService = new AuthenticationService(
                _mockUserRepository.Object,
                _mockSessionRepository.Object,
                _mockAuditRepository.Object);
        }

        #region Login Tests

        [Fact]
        public async Task LoginAsync_WithValidCredentials_ShouldReturnSuccess()
        {
            // Arrange
            string username = "testuser";
            string password = "Test@1234";
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(password, 12);
            
            var user = new User
            {
                Id = 1,
                Username = username,
                Email = "test@example.com",
                PasswordHash = passwordHash,
                IsActive = true,
                FailedLoginAttempts = 0,
                CreatedAt = System.DateTime.UtcNow
            };

            _mockUserRepository
                .Setup(x => x.GetUserByUsernameAsync(username))
                .ReturnsAsync(user);

            _mockSessionRepository
                .Setup(x => x.CreateSessionAsync(It.IsAny<int>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync(true);

            _mockUserRepository
                .Setup(x => x.UpdateLastSuccessfulLoginAsync(It.IsAny<int>()))
                .ReturnsAsync(true);

            _mockUserRepository
                .Setup(x => x.ResetFailedLoginAsync(It.IsAny<int>()))
                .ReturnsAsync(true);

            // Act
            var (success, token, message) = await _authService.LoginAsync(
                username, password, "192.168.1.1", "Mozilla/5.0");

            // Assert
            success.Should().BeTrue();
            token.Should().NotBeNullOrEmpty();
            message.Should().Contain("exitoso");
            
            _mockSessionRepository.Verify(
                x => x.CreateSessionAsync(It.IsAny<int>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()),
                Times.Once);
        }

        [Fact]
        public async Task LoginAsync_WithInvalidPassword_ShouldReturnFailure()
        {
            // Arrange
            string username = "testuser";
            string correctPassword = "Test@1234";
            string wrongPassword = "WrongPassword123";
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(correctPassword, 12);

            var user = new User
            {
                Id = 1,
                Username = username,
                Email = "test@example.com",
                PasswordHash = passwordHash,
                IsActive = true,
                FailedLoginAttempts = 0
            };

            _mockUserRepository
                .Setup(x => x.GetUserByUsernameAsync(username))
                .ReturnsAsync(user);

            _mockUserRepository
                .Setup(x => x.RecordFailedLoginAttemptAsync(It.IsAny<int>()))
                .ReturnsAsync(true);

            // Act
            var (success, token, message) = await _authService.LoginAsync(
                username, wrongPassword, "192.168.1.1", "Mozilla/5.0");

            // Assert
            success.Should().BeFalse();
            token.Should().BeNull();
            message.Should().Contain("inválidas");
            
            _mockUserRepository.Verify(
                x => x.RecordFailedLoginAttemptAsync(It.IsAny<int>()),
                Times.Once);
        }

        [Fact]
        public async Task LoginAsync_WithNonexistentUser_ShouldReturnFailure()
        {
            // Arrange
            string username = "nonexistent";
            string password = "Test@1234";

            _mockUserRepository
                .Setup(x => x.GetUserByUsernameAsync(username))
                .ReturnsAsync((User)null);

            // Act
            var (success, token, message) = await _authService.LoginAsync(
                username, password, "192.168.1.1", "Mozilla/5.0");

            // Assert
            success.Should().BeFalse();
            token.Should().BeNull();
            message.Should().Contain("inválidas");
        }

        [Fact]
        public async Task LoginAsync_WithInactiveUser_ShouldReturnFailure()
        {
            // Arrange
            string username = "testuser";
            string password = "Test@1234";
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(password, 12);

            var user = new User
            {
                Id = 1,
                Username = username,
                Email = "test@example.com",
                PasswordHash = passwordHash,
                IsActive = false  // ✅ Usuario inactivo
            };

            _mockUserRepository
                .Setup(x => x.GetUserByUsernameAsync(username))
                .ReturnsAsync(user);

            // Act
            var (success, token, message) = await _authService.LoginAsync(
                username, password, "192.168.1.1", "Mozilla/5.0");

            // Assert
            success.Should().BeFalse();
        }

        [Theory]
        [InlineData("")]
        [InlineData(null)]
        [InlineData("   ")]
        public async Task LoginAsync_WithEmptyUsername_ShouldReturnFailure(string username)
        {
            // Act
            var (success, token, message) = await _authService.LoginAsync(
                username, "Test@1234", "192.168.1.1", "Mozilla/5.0");

            // Assert
            success.Should().BeFalse();
        }

        [Fact]
        public async Task LoginAsync_WithLockedAccount_ShouldReturnFailure()
        {
            // Arrange
            string username = "testuser";
            string password = "Test@1234";
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(password, 12);

            var user = new User
            {
                Id = 1,
                Username = username,
                Email = "test@example.com",
                PasswordHash = passwordHash,
                IsActive = true,
                FailedLoginAttempts = 5,  // ✅ Cuenta bloqueada
                LastFailedLoginAttempt = System.DateTime.UtcNow.AddMinutes(-5)
            };

            _mockUserRepository
                .Setup(x => x.GetUserByUsernameAsync(username))
                .ReturnsAsync(user);

            // Act
            var (success, token, message) = await _authService.LoginAsync(
                username, password, "192.168.1.1", "Mozilla/5.0");

            // Assert
            success.Should().BeFalse();
            message.Should().Contain("bloqueada");
        }

        #endregion

        #region Registration Tests

        [Fact]
        public async Task RegisterUserAsync_WithValidData_ShouldReturnSuccess()
        {
            // Arrange
            string username = "newuser";
            string email = "newuser@example.com";
            string password = "SecurePass@123";

            _mockUserRepository
                .Setup(x => x.GetUserByUsernameAsync(username))
                .ReturnsAsync((User)null);

            _mockUserRepository
                .Setup(x => x.GetUserByEmailAsync(email))
                .ReturnsAsync((User)null);

            _mockUserRepository
                .Setup(x => x.CreateUserAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                .ReturnsAsync(true);

            // Act
            var (success, message) = await _authService.RegisterUserAsync(username, email, password);

            // Assert
            success.Should().BeTrue();
            message.Should().Contain("exitosamente");
            
            _mockUserRepository.Verify(
                x => x.CreateUserAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()),
                Times.Once);
        }

        [Fact]
        public async Task RegisterUserAsync_WithExistingUsername_ShouldReturnFailure()
        {
            // Arrange
            string username = "existinguser";
            var existingUser = new User { Id = 1, Username = username };

            _mockUserRepository
                .Setup(x => x.GetUserByUsernameAsync(username))
                .ReturnsAsync(existingUser);

            // Act
            var (success, message) = await _authService.RegisterUserAsync(
                username, "new@example.com", "SecurePass@123");

            // Assert
            success.Should().BeFalse();
            message.Should().Contain("ya existe");
        }

        [Fact]
        public async Task RegisterUserAsync_WithWeakPassword_ShouldReturnFailure()
        {
            // Arrange
            string username = "newuser";
            string email = "newuser@example.com";
            string weakPassword = "weak";  // ✅ Contraseña débil

            // Act
            var (success, message) = await _authService.RegisterUserAsync(
                username, email, weakPassword);

            // Assert
            success.Should().BeFalse();
            message.Should().NotBeNullOrEmpty();
        }

        [Theory]
        [InlineData("ab", "test@example.com", "SecurePass@123")]  // Username muy corto
        [InlineData("validuser", "invalidemail", "SecurePass@123")]  // Email inválido
        [InlineData("validuser", "test@example.com", "short")]  // Password muy corta
        public async Task RegisterUserAsync_WithInvalidData_ShouldReturnFailure(
            string username, string email, string password)
        {
            // Act
            var (success, message) = await _authService.RegisterUserAsync(username, email, password);

            // Assert
            success.Should().BeFalse();
        }

        #endregion

        #region ValidateCredentials Tests

        [Fact]
        public async Task ValidateCredentialsAsync_WithCorrectPassword_ShouldReturnTrue()
        {
            // Arrange
            string username = "testuser";
            string password = "Test@1234";
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(password, 12);

            var user = new User
            {
                Id = 1,
                Username = username,
                PasswordHash = passwordHash,
                IsActive = true
            };

            _mockUserRepository
                .Setup(x => x.GetUserByUsernameAsync(username))
                .ReturnsAsync(user);

            // Act
            var (isValid, returnedUser) = await _authService.ValidateCredentialsAsync(username, password);

            // Assert
            isValid.Should().BeTrue();
            returnedUser.Should().NotBeNull();
            returnedUser.Id.Should().Be(1);
        }

        [Fact]
        public async Task ValidateCredentialsAsync_WithIncorrectPassword_ShouldReturnFalse()
        {
            // Arrange
            string username = "testuser";
            string correctPassword = "Test@1234";
            string wrongPassword = "WrongPass@123";
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(correctPassword, 12);

            var user = new User
            {
                Id = 1,
                Username = username,
                PasswordHash = passwordHash,
                IsActive = true
            };

            _mockUserRepository
                .Setup(x => x.GetUserByUsernameAsync(username))
                .ReturnsAsync(user);

            // Act
            var (isValid, returnedUser) = await _authService.ValidateCredentialsAsync(username, wrongPassword);

            // Assert
            isValid.Should().BeFalse();
            returnedUser.Should().BeNull();
        }

        #endregion
    }
}