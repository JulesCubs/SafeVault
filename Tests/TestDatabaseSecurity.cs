using NUnit.Framework;
using SafeVault.Services;
using System.Threading.Tasks;

[TestFixture]
public class TestDatabaseSecurity
{
    private UserRepository _userRepository;
    private AuthenticationService _authService;
    private const string TestConnectionString = "Server=.;Database=SafeVaultDB;Trusted_Connection=true;";

    [SetUp]
    public void Setup()
    {
        _userRepository = new UserRepository(TestConnectionString);
        _authService = new AuthenticationService(_userRepository);
    }

    [Test]
    public async Task TestGetUserByUsername_WithSQLInjection_ReturnsNull()
    {
        // SQL Injection attempt
        string maliciousUsername = "admin' OR '1'='1' --";
        
        var user = await _userRepository.GetUserByUsernameAsync(maliciousUsername);
        
        Assert.That(user, Is.Null);
    }

    [Test]
    public async Task TestGetUserByEmail_WithSQLInjection_ReturnsNull()
    {
        // SQL Injection attempt
        string maliciousEmail = "admin@example.com' OR '1'='1' --";
        
        var user = await _userRepository.GetUserByEmailAsync(maliciousEmail);
        
        Assert.That(user, Is.Null);
    }

    [Test]
    public async Task TestSearchUsers_WithSQLInjection_HandledSafely()
    {
        // SQL Injection attempt en búsqueda
        string maliciousSearch = "'; DROP TABLE Users; --";
        
        var users = await _userRepository.SearchUsersAsync(maliciousSearch);
        
        Assert.That(users, Is.Not.Null);
        Assert.That(users.Count, Is.EqualTo(0));
    }

    [Test]
    public async Task TestValidateCredentials_WithSQLInjection_ReturnsFalse()
    {
        string maliciousUsername = "admin' OR '1'='1";
        string password = "anypassword";
        
        var (isValid, user) = await _authService.ValidateCredentialsAsync(maliciousUsername, password);
        
        Assert.That(isValid, Is.False);
        Assert.That(user, Is.Null);
    }

    [Test]
    public async Task TestValidateCredentials_WithInvalidUsername_ReturnsFalse()
    {
        string invalidUsername = "user@#$%";
        string password = "password123";
        
        var (isValid, user) = await _authService.ValidateCredentialsAsync(invalidUsername, password);
        
        Assert.That(isValid, Is.False);
    }

    [Test]
    public async Task TestRegisterUser_WithValidData_Succeeds()
    {
        string username = "testuser123";
        string email = "test@example.com";
        string password = "SecurePassword123!";
        
        var (success, message) = await _authService.RegisterUserAsync(username, email, password);
        
        Assert.That(success, Is.True);
        Assert.That(message, Does.Contain("exitosamente"));
    }

    [Test]
    public async Task TestRegisterUser_WithShortPassword_Fails()
    {
        string username = "testuser";
        string email = "test@example.com";
        string password = "short";
        
        var (success, message) = await _authService.RegisterUserAsync(username, email, password);
        
        Assert.That(success, Is.False);
        Assert.That(message, Does.Contain("8 caracteres"));
    }

    [Test]
    public async Task TestRegisterUser_WithInvalidEmail_Fails()
    {
        string username = "testuser";
        string email = "invalidemail";
        string password = "SecurePassword123!";
        
        var (success, message) = await _authService.RegisterUserAsync(username, email, password);
        
        Assert.That(success, Is.False);
        Assert.That(message, Does.Contain("Email inválido"));
    }
}