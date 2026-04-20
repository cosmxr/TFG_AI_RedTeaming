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
        // GET / o GET /Dashboard
        // Lanza TODAS las consultas en paralelo con Task.WhenAll
        // para evitar esperas secuenciales innecesarias.
        // ============================================================
        public async Task<IActionResult> Index()
        {
            _logger.LogInformation("Cargando Dashboard principal");

            try
            {
                // Lanzar todas las tareas a la vez sin await individual
                var taskTotalAuditorias = _dbService.GetTotalAuditoriasAsync();
                var taskTotalAtaques = _dbService.GetTotalAtaquesAsync();
                var taskPorcentaje = _dbService.GetPorcentajeVulnerablesAsync();
                var taskTiposDistintos = _dbService.GetTiposAtaqueDistintosAsync();
                var taskAtaquesPorTipo = _dbService.GetAtaquesPorTipoAsync();
                var taskAtaquesPorDia = _dbService.GetAtaquesPorDiaAsync();
                var taskUltimasAuditorias = _dbService.GetUltimasAuditoriasAsync(5);
                var taskApiActiva = _apiService.GetEstadoAsync();

                // Esperar a que todas terminen simultáneamente
                await Task.WhenAll(
                    taskTotalAuditorias, taskTotalAtaques, taskPorcentaje,
                    taskTiposDistintos, taskAtaquesPorTipo, taskAtaquesPorDia,
                    taskUltimasAuditorias, taskApiActiva
                );

                // Serializar datos de gráficos a JSON (se hace aquí, no en la vista)
                var jsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = null };
                var ataquesPorTipoJson = JsonSerializer.Serialize(await taskAtaquesPorTipo, jsonOptions);
                var ataquesPorDiaJson = JsonSerializer.Serialize(await taskAtaquesPorDia, jsonOptions);
                var apiActiva = await taskApiActiva;

                // Inyectar estado de la API en ViewData para el _Layout
                ViewData["ApiEstado"] = apiActiva;

                var viewModel = new DashboardViewModel
                {
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

                _logger.LogInformation("Dashboard cargado: {A} auditorías, {T} ataques",
                    viewModel.TotalAuditorias, viewModel.TotalAtaques);

                return View(viewModel);
            }
            catch (Exception ex)
            {
                // Si algo falla, mostrar Dashboard vacío con mensaje de error
                _logger.LogError(ex, "Error al cargar datos del Dashboard");
                ViewData["Error"] = "No se pudieron cargar los datos. Verifica que SQL Server LocalDB está activo.";
                ViewData["ApiEstado"] = false;
                return View(new DashboardViewModel());
            }
        }

        // ============================================================
        // GET /Dashboard/ApiEstado — Endpoint JSON para polling navbar
        // Llamado cada 30 segundos por el script de _Layout.cshtml
        // Devuelve: { "activo": true|false }
        // ============================================================
        [HttpGet]
        public async Task<IActionResult> ApiEstado()
        {
            _logger.LogDebug("Polling de estado de la API desde navbar");
            var activo = await _apiService.GetEstadoAsync();
            return Json(new { activo });
        }

        // ============================================================
        // GET /Dashboard/Error — Página de error genérica
        // ============================================================
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            ViewData["Title"] = "Error";
            return View();
        }
    }
}
