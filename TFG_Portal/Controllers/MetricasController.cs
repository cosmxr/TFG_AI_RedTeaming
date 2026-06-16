// ============================================================
// MetricasController.cs — v6.2 — timeouts corregidos
// Cambio en Exportar(): usa el cliente "FastAPI" (mismo nombre
// que ApiService) y añade CancellationTokenSource explícito.
// ============================================================

using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
using TFG_Portal.Models;
using TFG_Portal.Services;

namespace TFG_Portal.Controllers
{
    public class MetricasController : Controller
    {
        private readonly IDatabaseService _dbService;
        private readonly IApiService _apiService;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _config;
        private readonly ILogger<MetricasController> _logger;

        private const string SESSION_PROYECTO = "ProyectoActivoId";

        // Timeout específico para exportar CSV.
        // Debe ser menor que HttpClient.Timeout (40 min) para que
        // el CTS dispare antes que el cliente y el error sea descriptivo.
        private static readonly TimeSpan TimeoutExportar = TimeSpan.FromSeconds(90);

        public MetricasController(
            IDatabaseService dbService,
            IApiService apiService,
            IHttpClientFactory httpClientFactory,
            IConfiguration config,
            ILogger<MetricasController> logger)
        {
            _dbService = dbService;
            _apiService = apiService;
            _httpClientFactory = httpClientFactory;
            _config = config;
            _logger = logger;
        }

        // ────────────────────────────────────────────────────
        // GET /Metricas/Comparativa
        // ────────────────────────────────────────────────────
        public async Task<IActionResult> Comparativa()
        {
            var proyectoId = HttpContext.Session.GetInt32(SESSION_PROYECTO) ?? 0;
            var proyecto = await _dbService.GetProyectoByIdAsync(proyectoId);

            var comparativa = (await _dbService.GetComparativaModelosAsync(proyectoId)).ToList();
            var ranking = (await _dbService.GetRankingRobustezAsync(proyectoId)).ToList();

            var modelos = comparativa.Select(c => c.ModeloIa).Distinct().OrderBy(m => m).ToList();
            var tipos = comparativa.Select(c => c.TipoAtaque).Distinct().OrderBy(t => t).ToList();
            var indice = comparativa.ToDictionary(c => (c.ModeloIa, c.TipoAtaque), c => c);

            var jsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = null };
            var comparativaJson = JsonSerializer.Serialize(comparativa, jsonOptions);
            var rankingJson = JsonSerializer.Serialize(ranking, jsonOptions);

            ViewData["ApiEstado"] = await _apiService.GetEstadoAsync();
            ViewData["Proyecto"] = proyecto;
            ViewData["Modelos"] = modelos;
            ViewData["Tipos"] = tipos;
            ViewData["Indice"] = indice;
            ViewData["Ranking"] = ranking;
            ViewData["ComparativaJson"] = comparativaJson;
            ViewData["RankingJson"] = rankingJson;

            return View();
        }

        // ────────────────────────────────────────────────────
        // GET /Metricas/Ranking
        // ────────────────────────────────────────────────────
        public async Task<IActionResult> Ranking()
        {
            var proyectoId = HttpContext.Session.GetInt32(SESSION_PROYECTO) ?? 0;
            var proyecto = await _dbService.GetProyectoByIdAsync(proyectoId);
            var ranking = (await _dbService.GetRankingRobustezAsync(proyectoId)).ToList();

            var jsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = null };
            ViewData["RankingJson"] = JsonSerializer.Serialize(ranking, jsonOptions);
            ViewData["ApiEstado"] = await _apiService.GetEstadoAsync();
            ViewData["Proyecto"] = proyecto;

            return View(ranking);
        }

        // ────────────────────────────────────────────────────
        // GET /Metricas/Evolucion
        // ────────────────────────────────────────────────────
        public async Task<IActionResult> Evolucion()
        {
            var proyectoId = HttpContext.Session.GetInt32(SESSION_PROYECTO) ?? 0;
            var proyecto = await _dbService.GetProyectoByIdAsync(proyectoId);

            var porDia = await _dbService.GetAtaquesPorDiaAsync(proyectoId);
            var porSeveridad = await _dbService.GetAtaquesPorSeveridadAsync(proyectoId);
            var porTipo = await _dbService.GetAtaquesPorTipoAsync(proyectoId);

            var jsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = null };

            ViewData["ApiEstado"] = await _apiService.GetEstadoAsync();
            ViewData["Proyecto"] = proyecto;
            ViewData["PorDiaJson"] = JsonSerializer.Serialize(porDia, jsonOptions);
            ViewData["PorSevJson"] = JsonSerializer.Serialize(porSeveridad, jsonOptions);
            ViewData["PorTipoJson"] = JsonSerializer.Serialize(porTipo, jsonOptions);

            return View();
        }

        // ────────────────────────────────────────────────────
        // GET /Metricas/Exportar
        //
        // El portal actúa como proxy server-side:
        //   1. Llama a FastAPI internamente (red Docker)
        //   2. Recibe los bytes del CSV
        //   3. Los reenvía al navegador como File()
        //
        // Así el browser nunca ve tfg-api:8000.
        // ────────────────────────────────────────────────────
        public async Task<IActionResult> Exportar()
        {
            var proyectoId = HttpContext.Session.GetInt32(SESSION_PROYECTO) ?? 0;

            var apiActiva = await _apiService.GetEstadoAsync();
            if (!apiActiva)
            {
                TempData["Error"] =
                    "La API no está disponible. " +
                    "Verifica que el servicio FastAPI está corriendo.";
                return RedirectToAction("Comparativa");
            }

            var apiBase = _config.GetValue<string>("ApiSettings:BaseUrl")
                          ?? "http://tfg-api:8000";

            var csvUrl = $"{apiBase}/metricas/exportar?formato=csv&proyecto_id={proyectoId}";

            _logger.LogInformation(
                "Exportando CSV — proyecto {Id} — URL interna: {Url}",
                proyectoId, csvUrl);

            try
            {
                // Usamos el cliente "FastAPI" (misma instancia que ApiService)
                var client = _httpClientFactory.CreateClient("FastAPI");

                // CTS propio con 90 s — menor que HttpClient.Timeout (40 min)
                // para obtener un mensaje de error descriptivo si la query SQL
                // o la generación del CSV se cuelgan.
                using var cts = new CancellationTokenSource(TimeoutExportar);

                var response = await client.GetAsync(csvUrl, cts.Token);

                if (!response.IsSuccessStatusCode)
                {
                    var body = await response.Content.ReadAsStringAsync(cts.Token);
                    _logger.LogError(
                        "FastAPI {Status} al exportar CSV — proyecto {Id}: {Body}",
                        (int)response.StatusCode, proyectoId, body);

                    TempData["Error"] =
                        $"Error al generar el CSV (HTTP {(int)response.StatusCode}). " +
                        "Comprueba los logs del servicio Python.";
                    return RedirectToAction("Comparativa");
                }

                var csvBytes = await response.Content.ReadAsByteArrayAsync(cts.Token);
                var nombre = $"benchmark_red_teaming_proyecto{proyectoId}" +
                               $"_{DateTime.Now:yyyyMMdd_HHmmss}.csv";

                _logger.LogInformation(
                    "CSV generado — {Bytes} bytes — proyecto {Id}",
                    csvBytes.Length, proyectoId);

                return File(csvBytes, "text/csv; charset=utf-8", nombre);
            }
            catch (OperationCanceledException)
            {
                _logger.LogError(
                    "Timeout ({S}s) al exportar CSV — proyecto {Id}",
                    TimeoutExportar.TotalSeconds, proyectoId);

                TempData["Error"] =
                    $"La generación del CSV superó el límite de {TimeoutExportar.TotalSeconds}s. " +
                    "El dataset puede ser muy grande. " +
                    "Prueba filtrando por modelo o rango de fechas desde el endpoint directamente.";
                return RedirectToAction("Comparativa");
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex,
                    "Sin conexión con FastAPI al exportar CSV — proyecto {Id}", proyectoId);

                TempData["Error"] =
                    "No se pudo conectar con la API para generar el CSV. " +
                    "Verifica que el contenedor tfg-api está arriba.";
                return RedirectToAction("Comparativa");
            }
        }
    }
}