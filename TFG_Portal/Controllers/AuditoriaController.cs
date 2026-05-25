// ============================================================
// AuditoriaController.cs — Lanzar ataques y ver historial
// AI Red Teaming Platform - TFG Ingeniería Informática
// ============================================================

using Microsoft.AspNetCore.Mvc;
using TFG_Portal.Models;
using TFG_Portal.Services;

namespace TFG_Portal.Controllers
{
    public class AuditoriaController : Controller
    {
        private readonly IApiService _apiService;
        private readonly IDatabaseService _dbService;
        private readonly ILogger<AuditoriaController> _logger;
        private const string SESSION_PROYECTO = "ProyectoActivoId";

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

            // Obtener tipos desde la API (con fallback automático si falla)
            var tipos = await _apiService.ObtenerTiposAtaqueAsync();

            ViewData["ApiEstado"] = await _apiService.GetEstadoAsync();
            ViewData["TiposAtaque"] = tipos;           // TiposAtaqueResponse completo
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

            var tipos = await _apiService.ObtenerTiposAtaqueAsync();
            var apiActiva = await _apiService.GetEstadoAsync();

            ViewData["ApiEstado"] = apiActiva;
            ViewData["TiposAtaque"] = tipos;

            if (!apiActiva)
            {
                ViewData["Error"] = "La API no está disponible. " +
                    "Asegúrate de que Ollama y la FastAPI están activos.";
                return View();
            }

            if (string.IsNullOrWhiteSpace(tipoAtaque))
            {
                ViewData["Error"] = "Debes seleccionar un tipo de ataque.";
                return View();
            }

            // Validar que el tipo existe (clasico + ai_redteam)
            var todosLosTipos = tipos.Todos;
            if (!todosLosTipos.Contains(tipoAtaque.ToUpper()))
            {
                ViewData["Error"] = $"Tipo de ataque no reconocido: {tipoAtaque}";
                return View();
            }

            _logger.LogInformation("Lanzando ataque {Tipo} [{Cat}] en proyecto {Id}",
                tipoAtaque,
                CategoriasAtaque.ObtenerCategoria(tipoAtaque),
                proyectoId.Value);

            var resultado = await _apiService.LanzarAtaqueAsync(
                tipoAtaque, promptPersonalizado, proyectoId.Value);

            if (resultado == null)
            {
                ViewData["Error"] = "El ataque falló. " +
                    "Revisa que la API y Ollama están activos e inténtalo de nuevo.";
                return View();
            }

            return RedirectToAction("Detalle", new { id = resultado.AtaqueId });
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