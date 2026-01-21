-- database.sql
-- Esquema de base de datos seguro conforme a OWASP Top 10
-- Crear base de datos (si no existe)

-- Crear tabla de usuarios con columnas de auditoría y seguridad
CREATE TABLE Users (
    Id INT PRIMARY KEY IDENTITY(1,1),
    Username NVARCHAR(50) NOT NULL UNIQUE,
    Email NVARCHAR(100) NOT NULL UNIQUE,
    PasswordHash NVARCHAR(MAX) NOT NULL,
    CreatedAt DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    UpdatedAt DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    IsActive BIT NOT NULL DEFAULT 1,
    FailedLoginAttempts INT NOT NULL DEFAULT 0,
    LastFailedLoginAttempt DATETIME2 NULL,
    LastSuccessfulLogin DATETIME2 NULL,
    
    INDEX IX_Username (Username),
    INDEX IX_Email (Email),
    INDEX IX_IsActive (IsActive)
);

-- Crear tabla de roles
CREATE TABLE Roles (
    Id INT PRIMARY KEY IDENTITY(1,1),
    RoleName NVARCHAR(50) NOT NULL UNIQUE,
    Description NVARCHAR(200),
    CreatedAt DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    IsActive BIT NOT NULL DEFAULT 1,
    
    INDEX IX_RoleName (RoleName)
);

-- Crear tabla de relación Usuario-Rol
CREATE TABLE UserRoles (
    Id INT PRIMARY KEY IDENTITY(1,1),
    UserId INT NOT NULL,
    RoleID INT NOT NULL,
    AssignedAt DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    
    FOREIGN KEY (UserId) REFERENCES Users(Id),
    FOREIGN KEY (RoleID) REFERENCES Roles(Id),
    UNIQUE (UserId, RoleID),
    INDEX IX_UserId (UserId),
    INDEX IX_RoleID (RoleID)
);

-- Crear tabla de auditoría para rastrear cambios sensibles
CREATE TABLE AuditLog (
    AuditID INT PRIMARY KEY IDENTITY(1,1),
    UserId INT,
    Action NVARCHAR(100) NOT NULL,
    Details NVARCHAR(500),
    IPAddress NVARCHAR(45),
    UserAgent NVARCHAR(500),
    Timestamp DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    
    FOREIGN KEY (UserId) REFERENCES Users(Id),
    INDEX IX_UserId (UserId),
    INDEX IX_Timestamp (Timestamp),
    INDEX IX_Action (Action)
);

-- Crear tabla de sesiones para rastrear sesiones activas
CREATE TABLE Sessions (
    SessionID INT PRIMARY KEY IDENTITY(1,1),
    UserId INT NOT NULL,
    SessionToken NVARCHAR(MAX) NOT NULL UNIQUE,
    IPAddress NVARCHAR(45),
    UserAgent NVARCHAR(500),
    CreatedAt DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    ExpiresAt DATETIME2 NOT NULL,
    IsValid BIT NOT NULL DEFAULT 1,
    
    FOREIGN KEY (UserId) REFERENCES Users(Id),
    INDEX IX_UserId (UserId),
    INDEX IX_SessionToken (SessionToken),
    INDEX IX_ExpiresAt (ExpiresAt),
    INDEX IX_IsValid (IsValid)
);

-- Crear tabla de intentos de acceso fallidos para análisis de seguridad
CREATE TABLE FailedAccessAttempts (
    AttemptID INT PRIMARY KEY IDENTITY(1,1),
    Username NVARCHAR(50),
    IPAddress NVARCHAR(45),
    AttemptType NVARCHAR(50),
    Details NVARCHAR(500),
    Timestamp DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    
    INDEX IX_Timestamp (Timestamp),
    INDEX IX_IPAddress (IPAddress),
    INDEX IX_Username (Username)
);

-- Insertar roles por defecto
INSERT INTO Roles (RoleName, Description, IsActive, CreatedAt) VALUES 
('Admin', 'Administrador del sistema con acceso completo', 1, GETUTCDATE()),
('Manager', 'Gestor de contenidos y usuarios', 1, GETUTCDATE()),
('User', 'Usuario estándar de la plataforma', 1, GETUTCDATE()),
('Guest', 'Acceso limitado como invitado', 1, GETUTCDATE());

-- Crear índices adicionales para optimizar búsquedas
CREATE INDEX IX_Users_UpdatedAt ON Users(UpdatedAt);
CREATE INDEX IX_AuditLog_UserId_Timestamp ON AuditLog(UserId, Timestamp DESC);
CREATE INDEX IX_Sessions_UserId_IsValid ON Sessions(UserId, IsValid);

