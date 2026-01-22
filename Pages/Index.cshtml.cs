using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace SafeVault.Pages;

public class IndexModel : PageModel
{
    private readonly ILogger<IndexModel> _logger;

    public IndexModel(ILogger<IndexModel> logger)
    {
        _logger = logger;
    }

    public void OnGet()
    {
    }

    public IActionResult OnPost(string username, string email)
    {
        // Validar y desinfectar entradas
        if (!InputSanitizer.IsValidUsername(username))
        {
            ModelState.AddModelError("username", "El nombre de usuario contiene caracteres inválidos o tiene longitud incorrecta.");
            return Page();
        }

        if (!InputSanitizer.IsValidEmail(email))
        {
            ModelState.AddModelError("email", "El formato del email es inválido.");
            return Page();
        }

        // Desinfectar entradas
        string sanitizedUsername = InputSanitizer.SanitizeInput(username);
        string sanitizedEmail = InputSanitizer.SanitizeInput(email);

        // Logging seguro: No interpolar datos de usuario directamente
        _logger.LogInformation("Formulario enviado - Usuario registrado en aplicación");

        // Aquí puedes procesar los datos seguros
        ViewData["Message"] = "Datos recibidos correctamente";
        return Page();
    }
}
