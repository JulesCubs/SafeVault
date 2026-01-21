-- database.sql
-- Esquema de base de datos seguro conforme a OWASP Top 10

-- Crear tabla de usuarios con columnas de auditoría y seguridad
CREATE TABLE Users (
    UserID INT PRIMARY KEY IDENTITY(1,1),
    Username VARCHAR(50) NOT NULL UNIQUE,
    Email VARCHAR(100) NOT NULL UNIQUE,
    PasswordHash VARCHAR(255) NOT NULL,
    CreatedAt DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    UpdatedAt DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    IsActive BIT NOT NULL DEFAULT 1,
    FailedLoginAttempts INT NOT NULL DEFAULT 0,
    LastFailedLoginAttempt DATETIME2 NULL,
    LastSuccessfulLogin DATETIME2 NULL,
    
    -- Índices para optimizar búsquedas
    INDEX IX_Username (Username),
    INDEX IX_Email (Email),
    INDEX IX_IsActive (IsActive)
);

-- Crear tabla de auditoría para rastrear cambios sensibles
CREATE TABLE AuditLog (
    AuditID INT PRIMARY KEY IDENTITY(1,1),
    UserId INT,
    Action NVARCHAR(100) NOT NULL,
    Details NVARCHAR(500),
    IPAddress VARCHAR(45),
    UserAgent NVARCHAR(500),
    Timestamp DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    
    FOREIGN KEY (UserId) REFERENCES Users(UserID),
    INDEX IX_UserId (UserId),
    INDEX IX_Timestamp (Timestamp)
);

-- Crear tabla de sesiones para rastrear sesiones activas
CREATE TABLE Sessions (
    SessionID INT PRIMARY KEY IDENTITY(1,1),
    UserId INT NOT NULL,
    SessionToken NVARCHAR(500) NOT NULL UNIQUE,
    IPAddress VARCHAR(45),
    UserAgent NVARCHAR(500),
    CreatedAt DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    ExpiresAt DATETIME2 NOT NULL,
    IsValid BIT NOT NULL DEFAULT 1,
    
    FOREIGN KEY (UserId) REFERENCES Users(UserID),
    INDEX IX_UserId (UserId),
    INDEX IX_SessionToken (SessionToken),
    INDEX IX_ExpiresAt (ExpiresAt)
);

-- Crear tabla de intentos de acceso fallidos para análisis de seguridad
CREATE TABLE FailedAccessAttempts (
    AttemptID INT PRIMARY KEY IDENTITY(1,1),
    Username NVARCHAR(50),
    IPAddress VARCHAR(45),
    AttemptType NVARCHAR(50),
    Details NVARCHAR(500),
    Timestamp DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    
    INDEX IX_Timestamp (Timestamp),
    INDEX IX_IPAddress (IPAddress)
);

-- Crear tabla de roles
CREATE TABLE Roles (
    RoleID INT PRIMARY KEY IDENTITY(1,1),
    RoleName NVARCHAR(50) NOT NULL UNIQUE,
    Description NVARCHAR(200),
    CreatedAt DATETIME2 NOT NULL DEFAULT GETUTCDATE()
);

-- Crear tabla de relación Usuario-Rol
CREATE TABLE UserRoles (
    UserRoleID INT PRIMARY KEY IDENTITY(1,1),
    UserId INT NOT NULL,
    RoleID INT NOT NULL,
    AssignedAt DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    
    FOREIGN KEY (UserId) REFERENCES Users(UserID),
    FOREIGN KEY (RoleID) REFERENCES Roles(RoleID),
    UNIQUE (UserId, RoleID),
    INDEX IX_UserId (UserId),
    INDEX IX_RoleID (RoleID)
);

-- Insertar roles por defecto
INSERT INTO Roles (RoleName, Description) VALUES 
('Admin', 'Administrador del sistema'),
('User', 'Usuario estándar'),
('Manager', 'Gestor de contenidos');

