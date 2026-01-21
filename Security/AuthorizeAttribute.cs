using System;

namespace SafeVault.Security
{
    /// <summary>
    /// Atributo para restringir acceso por rol
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class AuthorizeAttribute : Attribute
    {
        public string[] AllowedRoles { get; }

        public AuthorizeAttribute(params string[] roles)
        {
            AllowedRoles = roles ?? new string[] { };
        }
    }

    /// <summary>
    /// Atributo para permitir acceso sin autenticación
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class AllowAnonymousAttribute : Attribute
    {
    }
}