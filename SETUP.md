# SafeVault - Guía de Setup

## Descripción
SafeVault es una aplicación ASP.NET Core 9.0 implementada con seguridad conforme a OWASP Top 10. Incluye autenticación, autorización, gestión de roles, auditoría y protección contra ataques comunes.

## Requisitos Previos

- **.NET 9.0 SDK** o superior
- **SQL Server 2019** o superior (o SQL Server Express)
- **Visual Studio Code** o cualquier editor con soporte C#
- **Git**

## Configuración Inicial

### 1. Clonar o Descargar el Proyecto

```bash
cd /path/to/SafeVault
```

### 2. Restaurar Dependencias

```bash
dotnet restore
```

### 3. Configurar la Base de Datos

#### Opción A: Usar SQL Server Express (Recomendado para desarrollo)

1. Asegúrate de tener SQL Server Express instalado
2. Abre SQL Server Management Studio
3. Conéctate al servidor local
4. Ejecuta el script: `Data/database.sql`

#### Opción B: Configurar manualmente

```sql
-- Ejecutar este comando en SQL Server Management Studio o Azure Data Studio
CREATE DATABASE SafeVault;
USE SafeVault;
-- Luego ejecutar el contenido del archivo Data/database.sql
```

### 4. Configurar Connection String

Edita el archivo `appsettings.json`:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(local)\\SQLEXPRESS;Database=SafeVault;Integrated Security=true;TrustServerCertificate=True;MultipleActiveResultSets=true;"
  }
}
```

**Nota**: Reemplaza `(local)\SQLEXPRESS` con tu servidor SQL Server si es diferente.

### 5. Compilar el Proyecto

```bash
dotnet build
```

### 6. Ejecutar las Pruebas

```bash
dotnet test
```

### 7. Iniciar la Aplicación

```bash
dotnet run
```

La aplicación estará disponible en:
- **HTTPS**: https://localhost:5001
- **HTTP**: http://localhost:5000

## Endpoints de la API

### Autenticación

#### Registrar Usuario
```bash
POST /api/auth/register
Content-Type: application/json

{
  "username": "testuser",
  "email": "test@example.com",
  "password": "SecurePass@123"
}
```

#### Login
```bash
POST /api/auth/login
Content-Type: application/json

{
  "username": "testuser",
  "password": "SecurePass@123"
}
```

Respuesta:
```json
{
  "success": true,
  "token": "base64_encoded_session_token",
  "message": "Login exitoso"
}
```

#### Logout
```bash
POST /api/auth/logout
Authorization: Bearer <session_token>
```

### Usuario

#### Obtener Perfil
```bash
GET /api/user/profile
Authorization: Bearer <session_token>
```

#### Cambiar Contraseña
```bash
POST /api/user/change-password
Authorization: Bearer <session_token>
Content-Type: application/json

{
  "username": "testuser",
  "currentPassword": "SecurePass@123",
  "newPassword": "NewPass@456"
}
```

### Admin

#### Obtener Todos los Usuarios
```bash
GET /api/admin/users
Authorization: Bearer <admin_token>
```

#### Obtener Roles Disponibles
```bash
GET /api/admin/roles
Authorization: Bearer <admin_token>
```

#### Asignar Rol a Usuario
```bash
POST /api/admin/users/{userId}/roles
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "roleName": "Admin"
}
```

## Características de Seguridad

### Implementadas conforme a OWASP Top 10:

1. **A01:2021 - Broken Access Control**
   - Validación de roles en cada acción
   - Control de acceso granular

2. **A02:2021 - Cryptographic Failures**
   - Hashing de contraseñas con BCrypt (workFactor 12)
   - Tokens de sesión seguros

3. **A03:2021 - Injection**
   - Consultas parametrizadas contra SQL Injection
   - Validación y sanitización de entrada

4. **A07:2021 - Authentication Failures**
   - Bloqueo de cuenta por intentos fallidos (5 intentos)
   - Timeout de sesión (30 minutos)
   - Rate limiting

5. **A09:2021 - Logging and Monitoring Failures**
   - Auditoría completa de acciones
   - Registro de intentos fallidos
   - Log de cambios sensibles

## Validación de Entrada

### Username
- Mínimo 3 caracteres
- Máximo 50 caracteres
- Solo letras, números, guiones y guiones bajos

### Email
- Formato válido según RFC 5322
- Máximo 100 caracteres

### Contraseña
- Mínimo 8 caracteres
- Máximo 128 caracteres
- Debe contener:
  - Al menos una mayúscula
  - Al menos una minúscula
  - Al menos un número
  - Al menos un carácter especial

## Estructura del Proyecto

```
SafeVault/
├── Controllers/          # Controladores API
├── Models/              # Modelos de datos
├── Services/            # Servicios de negocio
├── Data/               # Repositorios y scripts BD
├── Security/           # Seguridad y auditoría
├── Middleware/         # Middleware personalizado
├── Attributes/         # Atributos de autorización
├── Tests/              # Pruebas unitarias
├── wwwroot/            # Archivos estáticos
└── Pages/              # Páginas Razor
```

## Variables de Entorno Recomendadas

```bash
# Para producción
ASPNETCORE_ENVIRONMENT=Production
ASPNETCORE_URLS=https://0.0.0.0:443
SAFEVAULT_CONNECTION_STRING=Server=prod-server;Database=SafeVault;User Id=sa;Password=***;
```

## Troubleshooting

### Error de Conexión a BD

**Problema**: "Cannot connect to database"

**Solución**:
1. Verifica que SQL Server está ejecutándose
2. Verifica la connection string en `appsettings.json`
3. Asegúrate de que la BD existe
4. Ejecuta el script `Data/database.sql`

### Error de Compilación

**Problema**: "The type or namespace name 'X' could not be found"

**Solución**:
```bash
dotnet clean
dotnet restore
dotnet build
```

### Error de Autenticación

**Problema**: "401 Unauthorized"

**Solución**:
1. Verifica que el token es válido
2. Verifica que el header es: `Authorization: Bearer <token>`
3. Intenta registrar un nuevo usuario e iniciar sesión

## Contribución

Para contribuir al proyecto:
1. Crea una rama para tu feature
2. Asegúrate de que todas las pruebas pasan
3. Cumple con los estándares de seguridad OWASP
4. Realiza un Pull Request

## Licencia

Este proyecto está bajo la licencia especificada en `LICENSE`

## Soporte

Para reportar problemas o sugerencias, contacta al equipo de desarrollo.

---

**Última actualización**: 2024
**Versión**: 1.0.0
**Estado**: Producción Ready
