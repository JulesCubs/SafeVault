Ejecutar las pruebas
Corre los siguientes comandos en la terminal integrada:

# Navegar a la carpeta del proyecto
cd /home/julescubs/julian/dotnet/Auth_Security/SafeVault

# Restaurar dependencias
dotnet restore

# Ejecutar todas las pruebas
dotnet test Tests/TestInputValidation.cs -v normal

# Ejecutar pruebas con salida detallada
dotnet test Tests/TestInputValidation.cs --logger "console;verbosity=detailed"

# Ejecutar las Pruebas de Seguridad

## Pruebas de Inyección SQL y XSS

```bash
# Navegar a la carpeta del proyecto
cd /home/julescubs/julian/dotnet/Auth_Security/SafeVault

# Restaurar dependencias
dotnet restore

# Ejecutar todas las pruebas de validación
dotnet test Tests/TestInputValidation.cs -v normal

# Ejecutar pruebas de seguridad de base de datos
dotnet test Tests/TestDatabaseSecurity.cs -v normal

# Ejecutar todas las pruebas con salida detallada
dotnet test --logger "console;verbosity=detailed"

# Ejecutar pruebas específicas por nombre
dotnet test --filter "Name~SQLInjection"
dotnet test --filter "Name~XSS"

# Ejecutar pruebas con reporte de cobertura de código
dotnet test /p:CollectCoverage=true
```

## Características de Seguridad Implementadas

✅ **Sentencias Parametrizadas**: Todas las consultas SQL usan parámetros (@Parameter)
✅ **Validación de Entrada**: Sanitización con InputSanitizer
✅ **Hashing de Contraseña**: PBKDF2 con SHA256 y salt aleatorio
✅ **Protección SQL Injection**: Imposible con parámetros
✅ **Protección XSS**: Caracteres maliciosos eliminados
✅ **Búsquedas Seguras**: Términos sanitizados antes de LIKE

# Ejecutar todas las pruebas
dotnet test

# Ejecutar con verbosidad
dotnet test --verbosity detailed

# Ejecutar solo un archivo de pruebas
dotnet test SafeVault/Tests/AuthenticationServiceTests.cs

# Ver cobertura de código
dotnet test /p:CollectCoverageFormat=opencover