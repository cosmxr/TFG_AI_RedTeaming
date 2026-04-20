// ============================================================
// AuditoriaController.cs — Lanzar ataques y ver historial
// AI Red Teaming Platform - TFG Ingeniería Informática
// ============================================================

using Microsoft.AspNetCore.Mvc;
using TFG_Portal.Services;
using TFG_Portal.ViewModels;

namespace TFG_Portal.Controllers
{
    public class AuditoriaController : Controller
    {
        private readonly IApiService _apiService;
        private readonly IDatabaseService _dbService;
        private readonly ILogger<AuditoriaController> _logger;
        private const string SESSION_PROYECTO = "ProyectoActivoId";

        // Tipos de ataque disponibles
        private static readonly List<string> TiposAtaque =
            new() { "XSS", "SQLi", "LFI", "CSRF", "SSRF", "RCE" };

        public AuditoriaController(IApiService apiService,
                                    IDatabaseService dbService,
                                    ILogger<AuditoriaController> logger)
        {
            _apiService = apiService;
            _dbService = dbService;
            _logger = logger;
        }

        // ============================================================
        // GET /Auditoria/Nueva
        // ============================================================
        [HttpGet]
        public async Task<IActionResult> Nueva()
        {
            var proyectoId = HttpContext.Session.GetInt32(SESSION_PROYECTO);
            if (proyectoId == null)
                return RedirectToAction("Crear", "Proyecto");

            var proyecto = await _dbService.GetProyectoByIdAsync(proyectoId.Value);
            if (proyecto == null)
                return RedirectToAction("Crear", "Proyecto");

            var apiActiva = await _apiService.GetEstadoAsync();
            ViewData["ApiEstado"] = apiActiva;
            ViewData["TiposAtaque"] = TiposAtaque;
            ViewData["Proyecto"] = proyecto;

            return View();
        }

        // ============================================================
        // POST /Auditoria/Nueva — Lanza el ataque contra la IA
        // ============================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Nueva(string tipoAtaque,
                                                string? promptPersonalizado)
        {
            var proyectoId = HttpContext.Session.GetInt32(SESSION_PROYECTO);
            if (proyectoId == null)
                return RedirectToAction("Crear", "Proyecto");

            var apiActiva = await _apiService.GetEstadoAsync();
            ViewData["ApiEstado"] = apiActiva;
            ViewData["TiposAtaque"] = TiposAtaque;

            if (!apiActiva)
            {
                ViewData["Error"] = "La API de WhiteRabbitNeo no está disponible. Asegúrate de que Ollama y la FastAPI están activos.";
                return View();
            }

            if (string.IsNullOrWhiteSpace(tipoAtaque))
            {
                ViewData["Error"] = "Debes seleccionar un tipo de ataque.";
                return View();
            }

            _logger.LogInformation("Lanzando ataque {Tipo} en proyecto {Id}",
                tipoAtaque, proyectoId.Value);

            var resultado = await _apiService.LanzarAtaqueAsync(
                tipoAtaque, promptPersonalizado, proyectoId.Value);

            if (resultado == null)
            {
                ViewData["Error"] = "El ataque falló. Revisa que la API y Ollama están activos y vuelve a intentarlo.";
                return View();
            }

            // Redirigir al detalle del ataque recién creado
            return RedirectToAction("Detalle", new { id = resultado.Id });
        }

        // ============================================================
        // GET /Auditoria/Historial
        // ============================================================
        public async Task<IActionResult> Historial()
        {
            var proyectoId = HttpContext.Session.GetInt32(SESSION_PROYECTO) ?? 0;
            var proyecto = await _dbService.GetProyectoByIdAsync(proyectoId);

            var ataques = await _dbService.GetTodosAtaquesAsync(proyectoId);

            ViewData["ApiEstado"] = await _apiService.GetEstadoAsync();
            ViewData["Proyecto"] = proyecto;

            return View(ataques);
        }

        // ============================================================
        // GET /Auditoria/Detalle/{id}
        // ============================================================
        public async Task<IActionResult> Detalle(int id)
        {
            var detalle = await _dbService.GetAtaqueDetalleAsync(id);
            if (detalle == null)
            {
                _logger.LogWarning("Ataque ID {Id} no encontrado", id);
                return NotFound();
            }

            ViewData["ApiEstado"] = await _apiService.GetEstadoAsync();
            return View(detalle);
        }
    }
}