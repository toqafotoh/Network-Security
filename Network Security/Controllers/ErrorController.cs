using Microsoft.AspNetCore.Mvc;

namespace Network_Security.Controllers
{
    public class ErrorController : Controller
    {
        [Route("Error/Unauthorized")]
        public IActionResult Unauthorized()
        {
            return View(); // Views/Shared/Unauthorized.cshtml
        }

        [Route("Error/Forbidden")]
        public IActionResult Forbidden()
        {
            return View(); // Views/Shared/Forbidden.cshtml
        }
    }
}
