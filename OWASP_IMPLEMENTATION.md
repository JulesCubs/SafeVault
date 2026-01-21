# SafeVault - Implementación de OWASP Top 10

## Resumen de mejoras de seguridad implementadas

Este documento describe cómo SafeVault implementa las directrices de OWASP Top 10 para prevenir vulnerabilidades comunes en aplicaciones web.

---

## A01:2021 - Broken Access Control
**Problema:** Acceso no autorizado a recursos sensibles.

**Implementación:**
- ✅ Validación de usuario en cada operación de la base de datos
- ✅ Desactivación lógica de usuarios (`IsActive` field)
- ✅ Auditoría completa de acceso (`AuditLog` table)
- ✅ Sessions table con tokens seguros y expiración

**Archivos relacionados:**
- [Services/UserRepository.cs](Services/UserRepository.cs) - Validación en GetUserByUsername/Email
- [Security/OWASPCompliance.cs](Security/OWASPCompliance.cs) - SecurityAuditLogger

---

## A02:2021 - Cryptographic Failures
**Problema:** Exposición de datos sensibles sin encriptación.

**Implementación:**
- ✅ Hashing de contraseñas con PBKDF2 (10,000 iteraciones)
- ✅ UTC DateTime para timestamps (zona horaria consistente)
- ✅ Validación de hashes seguros en autenticación
- ✅ Nunca se almacenan contraseñas en texto plano

**Constantes de seguridad:**
```csharp
const int PBKDF2_ITERATIONS = 10000;
```

---

## A03:2021 - Injection
**Problema:** SQL Injection, Command Injection, XSS.

**Implementación:**
- ✅ **Sentencias parametrizadas** en todas las queries SQL
- ✅ **InputValidator** con validación de parámetros
- ✅ **SanitizeSearchTerm** para búsquedas seguras
- ✅ Validación de email con `System.Net.Mail.MailAddress`
- ✅ Limpieza de entrada (regex para alfanuméricos, guiones, guiones bajos)
- ✅ Rechazo de palabras SQL reservadas

**Ejemplo de SQL Injection prevention:**
```csharp
command.Parameters.AddWithValue("@Username", username);
```

---

## A04:2021 - Insecure Design
**Problema:** Falta de controles de seguridad en el diseño.

**Implementación:**
- ✅ Principio de **menor privilegio** (usuarios solo acceden a sus datos)
- ✅ **Validación en capas** (input → logic → database)
- ✅ **Rate limiting** con BruteForceProtection class
- ✅ **Lockout después de intentos fallidos** (5 intentos en 15 minutos)
- ✅ FailedLoginAttempts y LastFailedLoginAttempt tracking

---

## A05:2021 - Security Misconfiguration
**Problema:** Configuración insegura por defecto.

**Implementación:**
- ✅ Validación de cadena de conexión no vacía
- ✅ CommandTimeout = 30 segundos (prevenir DoS)
- ✅ IsActive = 1 (usuarios activos por defecto)
- ✅ FailedLoginAttempts = 0 (sin intentos fallidos inicialmente)

---

## A06:2021 - Vulnerable and Outdated Components
**Problema:** Uso de librerías con vulnerabilidades conocidas.

**Implementación:**
- ✅ Microsoft.Data.SqlClient 5.1.5 (última versión)
- ✅ NUnit 4.4.0 (framework de pruebas actualizado)
- ✅ .NET 9.0 (versión actual y soportada)
- ✅ Evitar RNGCryptoServiceProvider (obsoleto) → usar RandomNumberGenerator

---

## A07:2021 - Identification and Authentication Failures
**Problema:** Autenticación débil o tokens inseguros.

**Implementación:**
- ✅ **Validación de contraseña fuerte:**
  - Mínimo 12 caracteres
  - Requiere mayúsculas, minúsculas, números, caracteres especiales
  - Máximo 128 caracteres

- ✅ **BruteForceProtection:**
  - Máximo 5 intentos fallidos
  - Lockout de 15 minutos
  - Registro de LastFailedLoginAttempt

- ✅ **Sessions management:**
  - Token de sesión único por usuario
  - Expiración configurable
  - IP address tracking
  - User-Agent tracking

```csharp
public class BruteForceProtection
{
    const int MAX_FAILED_LOGIN_ATTEMPTS = 5;
    const int LOCKOUT_DURATION_MINUTES = 15;
}
```

---

## A08:2021 - Software and Data Integrity Failures
**Problema:** Falta de validación de integridad de datos.

**Implementación:**
- ✅ **Validación de entrada exhaustiva** antes de escribir en BD
- ✅ **UpdatedAt timestamp** en cada cambio
- ✅ **Transacciones seguras** con parámetros SQL
- ✅ **Verificación de duplicados** (Username, Email UNIQUE)

---

## A09:2021 - Logging and Monitoring Failures
**Problema:** Falta de auditoría de eventos de seguridad.

**Implementación:**
- ✅ **SecurityAuditLogger class** con métodos especializados:
  - LogAuthenticationAttempt
  - LogUserCreation
  - LogPasswordChange
  - LogUnauthorizedAccessAttempt
  - LogSqlException

- ✅ **AuditLog table** registra:
  - Acción realizada
  - Usuario afectado
  - IP address
  - User-Agent
  - Timestamp

- ✅ **FailedAccessAttempts table** para análisis de seguridad

```csharp
SecurityAuditLogger.LogAuthenticationAttempt(username, success, reason);
SecurityAuditLogger.LogUserCreation(username, email);
```

---

## A10:2021 - Server-Side Request Forgery (SSRF)
**Problema:** Aplicación realiza requests a URLs no validadas.

**Implementación:**
- ✅ Validación de email con estructura RFC 5322
- ✅ Rechazo de URLs malformadas
- ✅ Configuración segura de timeouts (30 segundos)
- ✅ Límites de entrada (username 50 chars, email 100 chars)

---

## Validaciones de Entrada

### Nombre de usuario
- **Largo:** 3-50 caracteres
- **Formato:** Alfanuméricos, guiones, guiones bajos
- **Validación:** Rechaza palabras SQL reservadas

### Email
- **Largo:** Hasta 100 caracteres
- **Formato:** RFC 5322 (validación oficial)
- **Unico:** Constraint UNIQUE en BD

### Contraseña
- **Largo:** 12-128 caracteres
- **Complejidad:**
  - Mayúsculas (A-Z)
  - Minúsculas (a-z)
  - Números (0-9)
  - Caracteres especiales (!@#$%^&*...)

---

## Base de Datos

### Tablas principales

1. **Users** - Información de usuario
   - UserID (PK)
   - Username (UNIQUE)
   - Email (UNIQUE)
   - PasswordHash (PBKDF2)
   - IsActive (control de acceso)
   - FailedLoginAttempts (rate limiting)
   - LastFailedLoginAttempt (auditoría)
   - LastSuccessfulLogin (auditoría)

2. **AuditLog** - Registro de cambios sensibles
3. **Sessions** - Gestión de sesiones activas
4. **FailedAccessAttempts** - Análisis de intentos fallidos

---

## Recomendaciones Adicionales

1. **HTTPS obligatorio** en producción
2. **CORS configurado correctamente** para prevenir ataques cross-origin
3. **Rate limiting global** en el API gateway
4. **WAF (Web Application Firewall)** en producción
5. **Monitoreo de logs** en tiempo real
6. **Backups regulares** encriptados
7. **Penetration testing** regular
8. **Code review** de seguridad antes de deployment

---

## Testing

Ver [Tests/TestInputValidation.cs](Tests/TestInputValidation.cs) para pruebas de:
- SQL Injection prevention
- XSS prevention
- Validación de contraseña
- Validación de email

---

**Última actualización:** 19 de Enero, 2026
**Conformidad:** OWASP Top 10 2021
