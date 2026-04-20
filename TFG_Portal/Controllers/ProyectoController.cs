// ============================================================
// ProyectoController.cs — Gestión de proyectos
// AI Red Teaming Platform - TFG Ingeniería Informática
// ============================================================

using Microsoft.AspNetCore.Mvc;
using TFG_Portal.Services;

namespace TFG_Portal.Controllers
{
    public class ProyectoController : Controller
    {
        private readonly IDatabaseService _dbService;
        private readonly ILogger<ProyectoController> _logger;
        private const string SESSION_PROYECTO = "ProyectoActivoId";

        public ProyectoController(IDatabaseService dbService,
                                   ILogger<ProyectoController> logger)
        {
            _dbService = dbService;
            _logger = logger;
        }

        // ============================================================
        // GET /Proyecto/Crear — Formulario de nuevo proyecto
        // ============================================================
        [HttpGet]
        public IActionResult Crear()
        {
            return View();
        }

        // ============================================================
        // POST /Proyecto/Crear — Guardar nuevo proyecto en BD
        // ============================================================
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Crear(string nombre,
                                               string? descripcion,
                                               string? modeloIa)
        {
            if (string.IsNullOrWhiteSpace(nombre))
            {
                ModelState.AddModelError("nombre", "El nombre es obligatorio.");
                return View();
            }

            var newId = await _dbService.CreateProyectoAsync(nombre, descripcion, modeloIa);

            if (newId == 0)
            {
                ViewData["Error"] = "No se pudo crear el proyecto. Inténtalo de nuevo.";
                return View();
            }

            // Activar automáticamente el proyecto recién creado
            HttpContext.Session.SetInt32(SESSION_PROYECTO, newId);
            _logger.LogInformation("Proyecto '{Nombre}' creado y activado (ID: {Id})",
                nombre, newId);

            return RedirectToAction("Index", "Dashboard");
        }

        // ============================================================
        // POST /Proyecto/Seleccionar — Cambiar proyecto activo
        // Llamado desde el selector del sidebar
        // ============================================================
        [HttpPost]
        public IActionResult Seleccionar(int proyectoId)
        {
            HttpContext.Session.SetInt32(SESSION_PROYECTO, proyectoId);
            _logger.LogInformation("Proyecto activo cambiado a ID: {Id}", proyectoId);
            return RedirectToAction("Index", "Dashboard");
        }
    }
}