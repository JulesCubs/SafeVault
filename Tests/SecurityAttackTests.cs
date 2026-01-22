using Xunit;
using SafeVault.Services;
using SafeVault.Security;
using SafeVault.Data;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SafeVault.Tests
{
    /// <summary>
    /// Suite de pruebas de seguridad que simulan ataques reales
    /// y verifican que el código corregido los bloquea efectivamente
    /// </summary>
    public class SecurityAttackTests
    {
        private readonly string _testConnectionString = 
            "Server=.;Database=SafeVault;Integrated Security=true;";

        #region SQL Injection Prevention Tests

        /// <summary>
        /// Test 1.1: Ataque UNION-based SQL Injection
        /// </summary>
        [Fact]
        public async Task Test_SQLInjection_UnionBased_ShouldBlockAttack()
        {
            // Arrange
            var userRepository = new UserRepository(_testConnectionString);
            var maliciousInput = "admin' UNION SELECT UserID, Username, Email, PasswordHash, IsActive FROM Users WHERE '1'='1";
            
            // Act
            var user = await userRepository.GetUserByUsernameAsync(maliciousInput);
            
            // Assert
            Assert.Null(user);
        }

        /// <summary>
        /// Test 1.2: Ataque Boolean-based Blind SQL Injection
        /// </summary>
        [Fact]
        public async Task Test_SQLInjection_BooleanBased_ShouldBlockAttack()
        {
            // Arrange
            var userRepository = new UserRepository(_testConnectionString);
            var maliciousInput = "admin' OR '1'='1";
            
            // Act
            var user = await userRepository.GetUserByUsernameAsync(maliciousInput);
            
            // Assert
            Assert.Null(user);
        }

        /// <summary>
        /// Test 1.3: Ataque Time-based Blind SQL Injection
        /// </summary>
        [Fact]
        public async Task Test_SQLInjection_TimeBasedBlind_ShouldNotDelay()
        {
            // Arrange
            var userRepository = new UserRepository(_testConnectionString);
            var maliciousInput = "admin'; WAITFOR DELAY '00:00:05'--";
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            
            // Act
            var user = await userRepository.GetUserByUsernameAsync(maliciousInput);
            stopwatch.Stop();
            
            // Assert
            Assert.Null(user);
            Assert.True(stopwatch.ElapsedMilliseconds < 2000);
        }

        /// <summary>
        /// Test 1.4: Ataque Stacked Queries SQL Injection
        /// </summary>
        [Fact]
        public async Task Test_SQLInjection_StackedQueries_ShouldBlockDrop()
        {
            // Arrange
            var userRepository = new UserRepository(_testConnectionString);
            var maliciousInput = "admin'; DROP TABLE Users; --";
            
            // Act
            var user = await userRepository.GetUserByUsernameAsync(maliciousInput);
            
            // Assert
            Assert.Null(user);
        }

        /// <summary>
        /// Test 1.5: Ataque Comment-based SQL Injection
        /// </summary>
        [Fact]
        public async Task Test_SQLInjection_CommentBased_ShouldBlockAttack()
        {
            // Arrange
            var userRepository = new UserRepository(_testConnectionString);
            var maliciousInput = "admin' /*-- bypass -- */";
            
            // Act
            var user = await userRepository.GetUserByUsernameAsync(maliciousInput);
            
            // Assert
            Assert.Null(user);
        }

        /// <summary>
        /// Test 1.6: Ataque Second-order SQL Injection
        /// </summary>
        [Fact]
        public async Task Test_SQLInjection_SecondOrder_ShouldBlockAttack()
        {
            // Arrange
            var userRepository = new UserRepository(_testConnectionString);
            var maliciousUsername = "test' UNION SELECT * FROM Users-- '" + Guid.NewGuid();
            var passwordHash = "hashedpassword123";
            
            // Act
            bool created = await userRepository.CreateUserAsync(
                username: maliciousUsername,
                email: $"test{Guid.NewGuid()}@example.com",
                passwordHash: passwordHash
            );
            
            // Assert
            Assert.True(created);
            var user = await userRepository.GetUserByUsernameAsync(maliciousUsername);
            Assert.NotNull(user);
            Assert.Equal(maliciousUsername, user.Username);
        }

        #endregion

        #region XSS Prevention Tests

        /// <summary>
        /// Test 2.1: Script Injection Attack
        /// </summary>
        [Fact]
        public void Test_XSS_ScriptInjection_ShouldBeEncoded()
        {
            // Arrange
            var maliciousInput = "<script>alert('XSS Attack')</script>";
            
            // Act
            var encoded = System.Net.WebUtility.HtmlEncode(maliciousInput);
            
            // Assert
            Assert.DoesNotContain("<script>", encoded);
            Assert.DoesNotContain("</script>", encoded);
            Assert.Contains("&lt;script&gt;", encoded);
            Assert.Contains("&lt;/script&gt;", encoded);
            Assert.Equal("&lt;script&gt;alert(&#39;XSS Attack&#39;)&lt;/script&gt;", encoded);
        }

        /// <summary>
        /// Test 2.2: Event Handler Injection
        /// </summary>
        [Fact]
        public void Test_XSS_EventHandlerInjection_ShouldBeEncoded()
        {
            // Arrange
            var maliciousInput = "<img src=x onerror=\"alert('Hacked')\">";
            
            // Act
            var encoded = System.Net.WebUtility.HtmlEncode(maliciousInput);
            
            // Assert
            Assert.DoesNotContain("onerror=", encoded);
            Assert.Contains("&lt;img", encoded);
            Assert.DoesNotContain("onerror=\"", encoded);
        }

        /// <summary>
        /// Test 2.3: Tag Closing/Injection XSS
        /// </summary>
        [Fact]
        public void Test_XSS_TagClosingInjection_ShouldBeEncoded()
        {
            // Arrange
            var maliciousInput = "</title><script>alert('XSS')</script><title>";
            
            // Act
            var encoded = System.Net.WebUtility.HtmlEncode(maliciousInput);
            var htmlOutput = $"<title>{encoded} - SafeVault</title>";
            
            // Assert
            Assert.DoesNotContain("</title>", htmlOutput);
            Assert.DoesNotContain("<script>", htmlOutput);
            Assert.Contains("&lt;/title&gt;", htmlOutput);
            Assert.Contains("&lt;script&gt;", htmlOutput);
        }

        /// <summary>
        /// Test 2.4: Attribute Breaking Injection
        /// </summary>
        [Fact]
        public void Test_XSS_AttributeBreakingInjection_ShouldBeEncoded()
        {
            // Arrange
            var maliciousInput = "\" onclick=\"alert('XSS')\" data=\"";
            
            // Act
            var encoded = System.Net.WebUtility.HtmlEncode(maliciousInput);
            var htmlAttribute = $"<div data-value=\"{encoded}\">Content</div>";
            
            // Assert
            Assert.DoesNotContain("onclick", htmlAttribute);
            Assert.DoesNotContain("\" onclick=\"", htmlAttribute);
        }

        /// <summary>
        /// Test 2.5: UTF-7 Encoding Bypass
        /// </summary>
        [Fact]
        public void Test_XSS_UTF7EncodingBypass_ShouldBeBlocked()
        {
            // Arrange
            var utf7Payload = "+ADw-script+AD4-alert(1)+ADw-/script+AD4-";
            
            // Act
            var sanitized = InputSanitizer.SanitizeInput(utf7Payload);
            var encoded = System.Net.WebUtility.HtmlEncode(sanitized);
            
            // Assert
            Assert.DoesNotContain("<script>", encoded.ToLower());
        }

        /// <summary>
        /// Test 2.6: Data URL XSS Injection
        /// </summary>
        [Fact]
        public void Test_XSS_DataURLInjection_ShouldBeBlocked()
        {
            // Arrange
            var maliciousInput = "javascript:alert('XSS')";
            
            // Act
            var sanitized = InputSanitizer.SanitizeInput(maliciousInput);
            var encoded = System.Net.WebUtility.HtmlEncode(sanitized);
            
            // Assert
            Assert.DoesNotContain("javascript:", encoded);
        }

        #endregion

        #region Input Validation Tests

        /// <summary>
        /// Test 3.1: Username validation - Too short
        /// </summary>
        [Fact]
        public void Test_Validation_UsernameTooShort_ShouldFail()
        {
            // Arrange
            var tooShort = "ab";
            
            // Act
            var (isValid, _) = InputValidator.ValidateUsername(tooShort);
            
            // Assert
            Assert.False(isValid);
        }

        /// <summary>
        /// Test 3.2: Username validation - Too long
        /// </summary>
        [Fact]
        public void Test_Validation_UsernameTooLong_ShouldFail()
        {
            // Arrange
            var tooLong = new string('a', 51);
            
            // Act
            var (isValid, _) = InputValidator.ValidateUsername(tooLong);
            
            // Assert
            Assert.False(isValid);
        }

        /// <summary>
        /// Test 3.3: Username with special characters
        /// </summary>
        [Fact]
        public void Test_Validation_UsernameWithSpecialChars_ShouldFail()
        {
            // Arrange
            var invalidUsernames = new[] { "admin<script>", "user';DROP--", "test@injection", "name!@#$%" };
            
            // Act & Assert
            foreach (var username in invalidUsernames)
            {
                var (isValid, _) = InputValidator.ValidateUsername(username);
                Assert.False(isValid, $"Username '{username}' should be invalid");
            }
        }

        /// <summary>
        /// Test 3.4: Email validation - Invalid formats
        /// </summary>
        [Fact]
        public void Test_Validation_InvalidEmailFormats_ShouldFail()
        {
            // Arrange
            var invalidEmails = new[] { "notanemail", "missing@domain", "@nodomain.com", "spaces in@email.com", "user@.com" };
            
            // Act & Assert
            foreach (var email in invalidEmails)
            {
                var (isValid, _) = InputValidator.ValidateEmail(email);
                Assert.False(isValid, $"Email '{email}' should be invalid");
            }
        }

        /// <summary>
        /// Test 3.5: Valid email formats should pass
        /// </summary>
        [Fact]
        public void Test_Validation_ValidEmailFormats_ShouldPass()
        {
            // Arrange
            var validEmails = new[] { "user@example.com", "test.user@domain.co.uk", "admin+tag@company.org" };
            
            // Act & Assert
            foreach (var email in validEmails)
            {
                var (isValid, _) = InputValidator.ValidateEmail(email);
                Assert.True(isValid, $"Email '{email}' should be valid");
            }
        }

        /// <summary>
        /// Test 3.6: Valid usernames should pass
        /// </summary>
        [Fact]
        public void Test_Validation_ValidUsername_ShouldPass()
        {
            // Arrange
            var validUsernames = new[] { "john_smith", "admin123", "user-test", "a1b2c3" };
            
            // Act & Assert
            foreach (var username in validUsernames)
            {
                var (isValid, _) = InputValidator.ValidateUsername(username);
                Assert.True(isValid, $"Username '{username}' should be valid");
            }
        }

        #endregion

        #region Sanitization Tests

        /// <summary>
        /// Test 3.7: Input sanitization removes dangerous characters
        /// </summary>
        [Fact]
        public void Test_Sanitization_DangerousCharactersRemoved()
        {
            // Arrange
            var testCases = new Dictionary<string, string>
            {
                { "admin<script>alert</script>", "" },
                { "test'; DROP--", "" },
                { "valid-user_123", "valid-user_123" },
                { "test!@#$%", "test" },
            };
            
            // Act & Assert
            foreach (var (input, expectedContains) in testCases)
            {
                var sanitized = InputSanitizer.SanitizeInput(input);
                Assert.DoesNotContain("<", sanitized);
                Assert.DoesNotContain(">", sanitized);
                Assert.DoesNotContain("'", sanitized);
                Assert.DoesNotContain(";", sanitized);
            }
        }

        #endregion

        #region Defense-In-Depth Tests

        /// <summary>
        /// Test verifying all 5 security layers work together
        /// </summary>
        [Fact]
        public async Task Test_DefenseInDepth_AllLayersActive()
        {
            // Arrange
            var userRepository = new UserRepository(_testConnectionString);
            var maliciousPayload = "<script>alert('XSS')</script>' OR '1'='1";
            
            // Act - Layer 1: Validation
            var (step1, _) = InputValidator.ValidateUsername(maliciousPayload);
            
            // Act - Layer 2: Sanitization
            var step2 = InputSanitizer.SanitizeInput(maliciousPayload);
            
            // Act - Layer 3: SQL Parametrization
            var step3 = await userRepository.GetUserByUsernameAsync(step2);
            
            // Act - Layer 4: HTML Encoding
            var step4 = System.Net.WebUtility.HtmlEncode(maliciousPayload);
            
            // Assert - Payload neutralized at each layer
            Assert.False(step1);                    // Validation rejects
            Assert.DoesNotContain("<", step2);      // Sanitization cleans
            Assert.Null(step3);                     // Parametrization blocks
            Assert.Contains("&lt;", step4);         // Encoding neutralizes
        }

        #endregion
    }
}
