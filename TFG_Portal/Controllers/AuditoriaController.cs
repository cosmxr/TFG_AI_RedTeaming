// ============================================================
// AuditoriaController.cs — Lanzar ataques, historial y benchmark
// AI Red Teaming Platform - TFG Ingeniería Informática
// v6.0 — añade Benchmark y ResultadoBenchmark
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

        public AuditoriaController(
            IApiService apiService,
            IDatabaseService dbService,
            ILogger<AuditoriaController> logger)
        {
            _apiService = apiService;
            _dbService = dbService;
            _logger = logger;
        }

        // ────────────────────────────────────────────────────
        // GET /Auditoria/Nueva
        // ────────────────────────────────────────────────────
        [HttpGet]
        public async Task<IActionResult> Nueva()
        {
            var proyectoId = HttpContext.Session.GetInt32(SESSION_PROYECTO);
            if (proyectoId == null)
                return RedirectToAction("Crear", "Proyecto");

            var proyecto = await _dbService.GetProyectoByIdAsync(proyectoId.Value);
            if (proyecto == null)
                return RedirectToAction("Crear", "Proyecto");

            ViewData["ApiEstado"] = await _apiService.GetEstadoAsync();
            ViewData["TiposAtaque"] = await _apiService.ObtenerTiposAtaqueAsync();
            ViewData["Proyecto"] = proyecto;
            return View();
        }

        // ────────────────────────────────────────────────────
        // POST /Auditoria/Nueva
        // ────────────────────────────────────────────────────
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

            if (!tipos.Todos.Contains(tipoAtaque.ToUpper()))
            {
                ViewData["Error"] = $"Tipo de ataque no reconocido: {tipoAtaque}";
                return View();
            }

            _logger.LogInformation(
                "Lanzando ataque {Tipo} [{Cat}] en proyecto {Id}",
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

        // ────────────────────────────────────────────────────
        // GET /Auditoria/Historial
        // ────────────────────────────────────────────────────
        public async Task<IActionResult> Historial()
        {
            var proyectoId = HttpContext.Session.GetInt32(SESSION_PROYECTO) ?? 0;
            var proyecto = await _dbService.GetProyectoByIdAsync(proyectoId);
            var ataques = await _dbService.GetTodosAtaquesAsync(proyectoId);

            ViewData["ApiEstado"] = await _apiService.GetEstadoAsync();
            ViewData["Proyecto"] = proyecto;
            return View(ataques);
        }

        // ────────────────────────────────────────────────────
        // GET /Auditoria/Detalle/{id}
        // ────────────────────────────────────────────────────
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

        // ────────────────────────────────────────────────────
        // GET /Auditoria/Benchmark
        // ────────────────────────────────────────────────────
        [HttpGet]
        public async Task<IActionResult> Benchmark()
        {
            var proyectoId = HttpContext.Session.GetInt32(SESSION_PROYECTO);
            if (proyectoId == null)
                return RedirectToAction("Crear", "Proyecto");

            var proyecto = await _dbService.GetProyectoByIdAsync(proyectoId.Value);
            if (proyecto == null)
                return RedirectToAction("Crear", "Proyecto");

            var apiActiva = await _apiService.GetEstadoAsync();

            // Modelos disponibles en Ollama
            var modelos = apiActiva
                ? await _apiService.ObtenerModelosAsync()
                : Enumerable.Empty<ModeloInfo>();

            // Metadatos de los 10 casos (sin prompts)
            var metadatos = apiActiva
                ? await _apiService.ObtenerBenchmarkAsync()
                : BenchmarkSuite.Ataques.Select(a => new BenchmarkMetadata
                {
                    TipoAtaque = a.TipoAtaque,
                    benchmark_id = a.Id,
                    Nombre = a.Nombre,
                    Tecnica = a.Tecnica,
                    Categoria = a.Categoria,
                    Severidad = a.Severidad,
                    OwaspRef = a.OwaspRef,
                    Referencia = a.Referencia,
                });

            // Historial de auditorías del proyecto
            var historial = await _dbService.GetUltimasAuditoriasAsync(
                proyectoId.Value, cantidad: 10);

            ViewData["ApiEstado"] = apiActiva;
            ViewData["Proyecto"] = proyecto;
            ViewData["Modelos"] = modelos;
            ViewData["Metadatos"] = metadatos;
            ViewData["Historial"] = historial;

            // Mostrar error de TempData si lo hay (viene del POST fallido)
            if (TempData["Error"] is string err)
                ViewData["Error"] = err;

            return View();
        }

        // ────────────────────────────────────────────────────
        // POST /Auditoria/Benchmark
        // ────────────────────────────────────────────────────
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Benchmark(
            string? modeloAuditado,
            List<string>? tiposAtaque)
        {
            var proyectoId = HttpContext.Session.GetInt32(SESSION_PROYECTO);
            if (proyectoId == null)
                return RedirectToAction("Crear", "Proyecto");

            var apiActiva = await _apiService.GetEstadoAsync();
            if (!apiActiva)
            {
                TempData["Error"] = "La API no está disponible. " +
                    "Asegúrate de que Ollama y la FastAPI están activos.";
                return RedirectToAction("Benchmark");
            }

            if (string.IsNullOrWhiteSpace(modeloAuditado))
            {
                TempData["Error"] = "Debes seleccionar un modelo para auditar.";
                return RedirectToAction("Benchmark");
            }

            _logger.LogInformation(
                "Lanzando benchmark — modelo: {Modelo} | proyecto: {Id} | tipos: {Tipos}",
                modeloAuditado,
                proyectoId.Value,
                tiposAtaque == null ? "todos" : string.Join(",", tiposAtaque));

            var resultado = await _apiService.LanzarBatchAsync(
                proyectoId.Value,
                modeloAuditado,
                tiposAtaque);

            if (resultado == null)
            {
                TempData["Error"] = "El benchmark falló o superó el tiempo límite. " +
                    "Revisa que la API y Ollama están activos e inténtalo de nuevo.";
                return RedirectToAction("Benchmark");
            }

            _logger.LogInformation(
                "Benchmark completado: auditoría #{Id} | {V}/{T} vulnerables ({Tasa}%)",
                resultado.AuditoriaId,
                resultado.TotalVulnerables,
                resultado.TotalAtaques,
                resultado.TasaVulnerabilidad);

            return RedirectToAction("ResultadoBenchmark",
                new { id = resultado.AuditoriaId });
        }

        // ────────────────────────────────────────────────────
        // GET /Auditoria/ResultadoBenchmark/{id}
        // ────────────────────────────────────────────────────
        public async Task<IActionResult> ResultadoBenchmark(int id)
        {
            var resultado = await _dbService.GetBenchmarkResultAsync(id);
            if (resultado == null)
            {
                _logger.LogWarning("Auditoría benchmark ID {Id} no encontrada", id);
                return NotFound();
            }

            var proyectoId = HttpContext.Session.GetInt32(SESSION_PROYECTO) ?? 0;
            var proyecto = await _dbService.GetProyectoByIdAsync(proyectoId);
            var ranking = await _dbService.GetRankingRobustezAsync(proyectoId);

            ViewData["ApiEstado"] = await _apiService.GetEstadoAsync();
            ViewData["Proyecto"] = proyecto;
            ViewData["Ranking"] = ranking;
            return View(resultado);
        }
    }
}