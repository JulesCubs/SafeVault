using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using SafeVault.Services;
using System.Threading.Tasks;

namespace SafeVault.Attributes
{
    public class AuthorizeRoleAttribute : Attribute, IAsyncAuthorizationFilter
    {
        private readonly string _requiredRole;

        public AuthorizeRoleAttribute(string requiredRole)
        {
            _requiredRole = requiredRole;
        }

        public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {
            var userId = (int?)context.HttpContext.Items["UserId"];
            
            if (userId == null)
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            var authzService = context.HttpContext.RequestServices
                .GetService(typeof(IAuthorizationService)) as IAuthorizationService;

            if (!await authzService.HasPermissionAsync(userId.Value, _requiredRole))
            {
                context.Result = new ForbidResult();
            }
        }
    }
}