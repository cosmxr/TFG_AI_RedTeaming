// ============================================================
// MetricasController.cs — Métricas y comparativa de modelos
// AI Red Teaming Platform - TFG Ingeniería Informática
// v6.0
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
        private readonly ILogger<MetricasController> _logger;
        private const string SESSION_PROYECTO = "ProyectoActivoId";

        public MetricasController(
            IDatabaseService dbService,
            IApiService apiService,
            ILogger<MetricasController> logger)
        {
            _dbService = dbService;
            _apiService = apiService;
            _logger = logger;
        }

        // ────────────────────────────────────────────────────
        // GET /Metricas/Comparativa
        // Heatmap modelo × tipo_ataque con tasa de vulnerabilidad.
        // Datos: ComparativaModelos (rellenada por el batch de Python)
        //        + RankingRobustez para el podio lateral.
        // ────────────────────────────────────────────────────
        public async Task<IActionResult> Comparativa()
        {
            var proyectoId = HttpContext.Session.GetInt32(SESSION_PROYECTO) ?? 0;
            var proyecto = await _dbService.GetProyectoByIdAsync(proyectoId);

            var comparativa = (await _dbService.GetComparativaModelosAsync(proyectoId)).ToList();
            var ranking = (await _dbService.GetRankingRobustezAsync(proyectoId)).ToList();

            // Pivote para el heatmap: modelos × tipos de ataque
            var modelos = comparativa.Select(c => c.ModeloIa).Distinct().OrderBy(m => m).ToList();
            var tipos = comparativa.Select(c => c.TipoAtaque).Distinct().OrderBy(t => t).ToList();

            // Índice rápido: (modelo, tipo) → fila
            var indice = comparativa.ToDictionary(
                c => (c.ModeloIa, c.TipoAtaque),
                c => c);

            // Serializar para Chart.js (barras agrupadas por modelo)
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
        // Tabla completa de robustez por modelo.
        // ────────────────────────────────────────────────────
        public async Task<IActionResult> Ranking()
        {
            var proyectoId = HttpContext.Session.GetInt32(SESSION_PROYECTO) ?? 0;
            var proyecto = await _dbService.GetProyectoByIdAsync(proyectoId);
            var ranking = (await _dbService.GetRankingRobustezAsync(proyectoId)).ToList();

            ViewData["ApiEstado"] = await _apiService.GetEstadoAsync();
            ViewData["Proyecto"] = proyecto;

            return View(ranking);
        }

        // ────────────────────────────────────────────────────
        // GET /Metricas/Evolucion
        // Gráfico de actividad y vulnerabilidades por día.
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
        // Redirige al endpoint CSV de la FastAPI.
        // ────────────────────────────────────────────────────
        public async Task<IActionResult> Exportar()
        {
            var proyectoId = HttpContext.Session.GetInt32(SESSION_PROYECTO) ?? 0;
            var apiActiva = await _apiService.GetEstadoAsync();

            if (!apiActiva)
            {
                TempData["Error"] = "La API no está disponible. " +
                    "No se puede generar el CSV en este momento.";
                return RedirectToAction("Comparativa");
            }

            // Obtener la URL base de la FastAPI desde configuración
            // y redirigir directamente al endpoint de descarga
            var apiBase = HttpContext.RequestServices
                .GetRequiredService<IConfiguration>()
                .GetValue<string>("ApiSettings:BaseUrl") ?? "http://tfg-api:8000";

            var csvUrl = $"{apiBase}/metricas/exportar?formato=csv&proyecto_id={proyectoId}";

            _logger.LogInformation("Exportando CSV para proyecto {Id}: {Url}",
                proyectoId, csvUrl);

            return Redirect(csvUrl);
        }
    }
}