// Tests/TestInputValidation.cs
using NUnit.Framework;
using System;

[TestFixture]
public class TestInputValidation
{
    private InputSanitizer _sanitizer;

    [SetUp]
    public void Setup()
    {
        _sanitizer = new InputSanitizer();
    }

    #region SQL Injection Tests
    
    [Test]
    public void TestForSQLInjection_SingleQuote()
    {
        // Intento de SQL Injection con comilla simple
        string maliciousInput = "admin' OR '1'='1";
        string result = InputSanitizer.SanitizeInput(maliciousInput);
        
        Assert.That(result, Does.Not.Contain("'"));
        Assert.That(result, Is.EqualTo("admin OR 11"));
    }

    [Test]
    public void TestForSQLInjection_DoubleQuote()
    {
        // Intento de SQL Injection con comilla doble
        string maliciousInput = "admin\" OR \"1\"=\"1";
        string result = InputSanitizer.SanitizeInput(maliciousInput);
        
        Assert.That(result, Does.Not.Contain("\""));
        Assert.That(result, Is.EqualTo("admin OR 11"));
    }

    [Test]
    public void TestForSQLInjection_Semicolon()
    {
        // Intento de SQL Injection con punto y coma (inyección de múltiples comandos)
        string maliciousInput = "user'; DROP TABLE users; --";
        string result = InputSanitizer.SanitizeInput(maliciousInput);
        
        Assert.That(result, Does.Not.Contain(";"));
        Assert.That(result, Does.Not.Contain("--"));
    }

    [Test]
    public void TestForSQLInjection_UnionSelect()
    {
        // Intento de SQL Injection con UNION SELECT
        string maliciousInput = "admin' UNION SELECT * FROM users --";
        string result = InputSanitizer.SanitizeInput(maliciousInput);
        
        Assert.That(result, Does.Not.Contain("'"));
        Assert.That(result, Does.Not.Contain("--"));
    }

    [Test]
    public void TestForSQLInjection_Comment()
    {
        // Intento de SQL Injection con comentarios SQL
        string maliciousInput = "admin' /**/OR/**/1=1";
        string result = InputSanitizer.SanitizeInput(maliciousInput);
        
        Assert.That(result, Does.Not.Contain("'"));
        Assert.That(result, Does.Not.Contain("/"));
    }

    #endregion

    #region XSS Tests

    [Test]
    public void TestForXSS_ScriptTag()
    {
        // Intento de XSS con etiqueta script
        string maliciousInput = "<script>alert('XSS')</script>";
        string result = InputSanitizer.SanitizeInput(maliciousInput);
        
        Assert.That(result, Does.Not.Contain("<script>"));
        Assert.That(result, Does.Not.Contain("</script>"));
        Assert.That(result, Does.Not.Contain("<"));
        Assert.That(result, Does.Not.Contain(">"));
    }

    [Test]
    public void TestForXSS_ImageTag()
    {
        // Intento de XSS con etiqueta img
        string maliciousInput = "<img src=x onerror=alert('XSS')>";
        string result = InputSanitizer.SanitizeInput(maliciousInput);
        
        Assert.That(result, Does.Not.Contain("<"));
        Assert.That(result, Does.Not.Contain(">"));
        Assert.That(result, Does.Not.Contain("onerror"));
    }

    [Test]
    public void TestForXSS_EventHandler()
    {
        // Intento de XSS con event handler
        string maliciousInput = "<div onclick=\"alert('XSS')\">Click me</div>";
        string result = InputSanitizer.SanitizeInput(maliciousInput);
        
        Assert.That(result, Does.Not.Contain("<"));
        Assert.That(result, Does.Not.Contain("onclick"));
        Assert.That(result, Does.Not.Contain("\""));
    }

    [Test]
    public void TestForXSS_JavascriptProtocol()
    {
        // Intento de XSS con protocolo javascript
        string maliciousInput = "<a href=\"javascript:alert('XSS')\">Link</a>";
        string result = InputSanitizer.SanitizeInput(maliciousInput);
        
        Assert.That(result, Does.Not.Contain("<"));
        Assert.That(result, Does.Not.Contain("javascript:"));
    }

    [Test]
    public void TestForXSS_SvgTag()
    {
        // Intento de XSS con etiqueta SVG
        string maliciousInput = "<svg onload=alert('XSS')>";
        string result = InputSanitizer.SanitizeInput(maliciousInput);
        
        Assert.That(result, Does.Not.Contain("<"));
        Assert.That(result, Does.Not.Contain("onload"));
    }

    #endregion

    #region Email Validation Tests

    [Test]
    public void TestValidEmail_Correct()
    {
        string validEmail = "user@example.com";
        bool result = InputSanitizer.IsValidEmail(validEmail);
        
        Assert.That(result, Is.True);
    }

    [Test]
    public void TestValidEmail_WithSQLInjection()
    {
        string maliciousEmail = "user@example.com'; DROP TABLE users; --";
        bool result = InputSanitizer.IsValidEmail(maliciousEmail);
        
        Assert.That(result, Is.False);
    }

    [Test]
    public void TestValidEmail_WithXSSAttempt()
    {
        string maliciousEmail = "user<script>alert('XSS')</script>@example.com";
        bool result = InputSanitizer.IsValidEmail(maliciousEmail);
        
        Assert.That(result, Is.False);
    }

    [Test]
    public void TestValidEmail_Invalid()
    {
        string invalidEmail = "notanemail";
        bool result = InputSanitizer.IsValidEmail(invalidEmail);
        
        Assert.That(result, Is.False);
    }

    #endregion

    #region Username Validation Tests

    [Test]
    public void TestValidUsername_Correct()
    {
        string validUsername = "user_123";
        bool result = InputSanitizer.IsValidUsername(validUsername);
        
        Assert.That(result, Is.True);
    }

    [Test]
    public void TestValidUsername_WithHyphens()
    {
        string validUsername = "user-name-123";
        bool result = InputSanitizer.IsValidUsername(validUsername);
        
        Assert.That(result, Is.True);
    }

    [Test]
    public void TestValidUsername_TooShort()
    {
        string shortUsername = "ab";
        bool result = InputSanitizer.IsValidUsername(shortUsername);
        
        Assert.That(result, Is.False);
    }

    [Test]
    public void TestValidUsername_TooLong()
    {
        string longUsername = "verylongusernamethatexceedsmax";
        bool result = InputSanitizer.IsValidUsername(longUsername);
        
        Assert.That(result, Is.False);
    }

    [Test]
    public void TestValidUsername_WithSpecialCharacters()
    {
        string maliciousUsername = "user@#$%^&*()";
        bool result = InputSanitizer.IsValidUsername(maliciousUsername);
        
        Assert.That(result, Is.False);
    }

    [Test]
    public void TestValidUsername_WithSQLInjection()
    {
        string maliciousUsername = "admin' OR '1'='1";
        bool result = InputSanitizer.IsValidUsername(maliciousUsername);
        
        Assert.That(result, Is.False);
    }

    #endregion

    #region Sanitization Tests

    [Test]
    public void TestSanitizeInput_Empty()
    {
        string result = InputSanitizer.SanitizeInput(string.Empty);
        
        Assert.That(result, Is.Empty);
    }

    [Test]
    public void TestSanitizeInput_Null()
    {
        string result = InputSanitizer.SanitizeInput(null);
        
        Assert.That(result, Is.Empty);
    }

    [Test]
    public void TestSanitizeInput_ValidInput()
    {
        string validInput = "john_doe-123";
        string result = InputSanitizer.SanitizeInput(validInput);
        
        Assert.That(result, Is.EqualTo("john_doe-123"));
    }

    [Test]
    public void TestSanitizeInput_MultipleAttacks()
    {
        // Combinación de SQL Injection y XSS
        string maliciousInput = "admin' <script>alert('XSS')</script> OR '1'='1";
        string result = InputSanitizer.SanitizeInput(maliciousInput);
        
        Assert.That(result, Does.Not.Contain("'"));
        Assert.That(result, Does.Not.Contain("<"));
        Assert.That(result, Does.Not.Contain(">"));
        Assert.That(result, Does.Not.Contain(";"));
    }

    #endregion
}
