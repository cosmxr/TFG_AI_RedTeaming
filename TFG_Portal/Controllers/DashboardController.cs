// ============================================================
// DashboardController.cs — Controlador del Dashboard principal
// AI Red Teaming Platform - TFG Ingeniería Informática
// ============================================================

using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using TFG_Portal.Services;
using TFG_Portal.ViewModels;

namespace TFG_Portal.Controllers
{
    public class DashboardController : Controller
    {
        private readonly IDatabaseService _dbService;
        private readonly IApiService _apiService;
        private readonly ILogger<DashboardController> _logger;

        // Clave de sesión para el proyecto activo
        private const string SESSION_PROYECTO = "ProyectoActivoId";

        public DashboardController(
            IDatabaseService dbService,
            IApiService apiService,
            ILogger<DashboardController> logger)
        {
            _dbService = dbService;
            _apiService = apiService;
            _logger = logger;
        }

        // ============================================================
        // GET /Dashboard o GET /Dashboard/Index
        // ============================================================
        public async Task<IActionResult> Index()
        {
            _logger.LogInformation("Cargando Dashboard principal");

            try
            {
                // --- Resolver proyecto activo ---
                var todosProyectos = (await _dbService.GetAllProyectosAsync()).ToList();

                // Si no hay proyectos, redirigir a crear el primero
                if (!todosProyectos.Any())
                    return RedirectToAction("Crear", "Proyecto");

                // Leer proyecto activo de la sesión, si no existe usar el primero
                var proyectoActivoId = HttpContext.Session.GetInt32(SESSION_PROYECTO)
                    ?? todosProyectos.First().Id;

                // Verificar que el proyecto de la sesión sigue existiendo
                if (!todosProyectos.Any(p => p.Id == proyectoActivoId))
                    proyectoActivoId = todosProyectos.First().Id;

                // Guardar en sesión
                HttpContext.Session.SetInt32(SESSION_PROYECTO, proyectoActivoId);

                var proyectoActivo = todosProyectos.First(p => p.Id == proyectoActivoId);

                // --- Lanzar todas las consultas en paralelo ---
                var taskTotalAuditorias = _dbService.GetTotalAuditoriasAsync(proyectoActivoId);
                var taskTotalAtaques = _dbService.GetTotalAtaquesAsync(proyectoActivoId);
                var taskPorcentaje = _dbService.GetPorcentajeVulnerablesAsync(proyectoActivoId);
                var taskTiposDistintos = _dbService.GetTiposAtaqueDistintosAsync(proyectoActivoId);
                var taskAtaquesPorTipo = _dbService.GetAtaquesPorTipoAsync(proyectoActivoId);
                var taskAtaquesPorDia = _dbService.GetAtaquesPorDiaAsync(proyectoActivoId);
                var taskUltimasAuditorias = _dbService.GetUltimasAuditoriasAsync(proyectoActivoId, 5);
                var taskApiActiva = _apiService.GetEstadoAsync();

                await Task.WhenAll(
                    taskTotalAuditorias, taskTotalAtaques, taskPorcentaje,
                    taskTiposDistintos, taskAtaquesPorTipo, taskAtaquesPorDia,
                    taskUltimasAuditorias, taskApiActiva
                );

                // --- Serializar JSON para Chart.js ---
                var jsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = null };
                var ataquesPorTipoJson = JsonSerializer.Serialize(
                    await taskAtaquesPorTipo, jsonOptions);
                var ataquesPorDiaJson = JsonSerializer.Serialize(
                    await taskAtaquesPorDia, jsonOptions);

                var apiActiva = await taskApiActiva;
                ViewData["ApiEstado"] = apiActiva;

                var viewModel = new DashboardViewModel
                {
                    ProyectoActivo = proyectoActivo,
                    TodosProyectos = todosProyectos,
                    TotalAuditorias = await taskTotalAuditorias,
                    TotalAtaques = await taskTotalAtaques,
                    PorcentajeVulnerables = await taskPorcentaje,
                    TiposAtaqueDistintos = await taskTiposDistintos,
                    AtaquesPorTipoJson = ataquesPorTipoJson,
                    AtaquesPorDiaJson = ataquesPorDiaJson,
                    UltimasAuditorias = await taskUltimasAuditorias,
                    ApiActiva = apiActiva,
                    FechaUltimaActualizacion = DateTime.Now
                };

                _logger.LogInformation(
                    "Dashboard cargado: proyecto={P}, {A} auditorías, {T} ataques",
                    proyectoActivo.Nombre, viewModel.TotalAuditorias, viewModel.TotalAtaques);

                return View(viewModel);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al cargar datos del Dashboard");
                ViewData["Error"] = "No se pudieron cargar los datos. Verifica que SQL Server LocalDB está activo.";
                ViewData["ApiEstado"] = false;
                return View(new DashboardViewModel());
            }
        }

        // ============================================================
        // POST /Dashboard/CambiarProyecto — Cambia el proyecto activo
        // Llamado desde el selector de la navbar/sidebar
        // ============================================================
        [HttpPost]
        public IActionResult CambiarProyecto(int proyectoId)
        {
            HttpContext.Session.SetInt32(SESSION_PROYECTO, proyectoId);
            _logger.LogInformation("Proyecto activo cambiado a ID: {Id}", proyectoId);
            return RedirectToAction("Index");
        }

        // ============================================================
        // GET /Dashboard/ApiEstado — Polling de estado de la API
        // ============================================================
        [HttpGet]
        public async Task<IActionResult> ApiEstado()
        {
            var activo = await _apiService.GetEstadoAsync();
            return Json(new { activo });
        }

        // ============================================================
        // GET /Dashboard/Error
        // ============================================================
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            ViewData["Title"] = "Error";
            return View();
        }
    }
}