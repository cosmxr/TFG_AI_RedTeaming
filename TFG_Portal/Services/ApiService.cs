// ============================================================
// ApiService.cs — Servicio que se comunica con la API FastAPI
// AI Red Teaming Platform - TFG Ingeniería Informática
// v6.0 — benchmark plano, sin nivel_prompt
// ============================================================

using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using TFG_Portal.Models;

namespace TFG_Portal.Services
{
    public class ApiService : IApiService
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<ApiService> _logger;
        private readonly JsonSerializerOptions _jsonOptions;

        // Benchmark completo: 10 ataques × ~1 min/ataque + margen
        private static readonly TimeSpan TimeoutBatch = TimeSpan.FromMinutes(35);
        // Ataque individual: 1 ejecución + evaluación del juez
        private static readonly TimeSpan TimeoutAtaque = TimeSpan.FromMinutes(5);

        // Fallback si la API no está disponible
        private static readonly TiposAtaqueResponse _fallback = new()
        {
            Clasico = new() { "XSS", "SQLI", "LFI", "CSRF" },
            AiRedteam = new()
            {
                "PROMPT_INJECTION", "JAILBREAK", "SYSTEM_PROMPT_LEAKAGE",
                "DATA_EXTRACTION", "CONTEXT_MANIPULATION", "INDIRECT_INJECTION"
            },
            Todos = new()
            {
                "XSS", "SQLI", "LFI", "CSRF",
                "PROMPT_INJECTION", "JAILBREAK", "SYSTEM_PROMPT_LEAKAGE",
                "DATA_EXTRACTION", "CONTEXT_MANIPULATION", "INDIRECT_INJECTION"
            }
        };

        public ApiService(IHttpClientFactory httpClientFactory,
                          ILogger<ApiService> logger)
        {
            _httpClientFactory = httpClientFactory;
            _logger = logger;
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                NumberHandling = JsonNumberHandling.AllowReadingFromString
            };
        }

        // ────────────────────────────────────────────────────────
        // GET /estado
        // ────────────────────────────────────────────────────────

        public async Task<bool> GetEstadoAsync()
        {
            try
            {
                var client = _httpClientFactory.CreateClient("FastAPI");
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var response = await client.GetAsync("/estado", cts.Token);
                var activa = response.IsSuccessStatusCode;
                _logger.LogInformation("Estado API FastAPI: {Estado}", activa ? "ACTIVA" : "INACTIVA");
                return activa;
            }
            catch (TaskCanceledException ex)
            {
                _logger.LogWarning("Timeout al comprobar estado API: {Msg}", ex.Message);
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogWarning("API FastAPI no disponible: {Msg}", ex.Message);
                return false;
            }
        }

        // ────────────────────────────────────────────────────────
        // GET /tipos_ataque
        // ────────────────────────────────────────────────────────

        public async Task<TiposAtaqueResponse> ObtenerTiposAtaqueAsync()
        {
            try
            {
                var client = _httpClientFactory.CreateClient("FastAPI");
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var response = await client.GetAsync("/tipos_ataque", cts.Token);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("Error {Code} al obtener tipos de ataque, usando fallback",
                        (int)response.StatusCode);
                    return _fallback;
                }

                var json = await response.Content.ReadAsStringAsync();
                var resultado = JsonSerializer.Deserialize<TiposAtaqueResponse>(json, _jsonOptions);

                if (resultado is null || !resultado.Todos.Any())
                {
                    _logger.LogWarning("Respuesta vacía de /tipos_ataque, usando fallback");
                    return _fallback;
                }

                _logger.LogInformation(
                    "Tipos obtenidos: {C} clásicos, {A} AI red team",
                    resultado.Clasico.Count, resultado.AiRedteam.Count);

                return resultado;
            }
            catch (TaskCanceledException)
            {
                _logger.LogWarning("Timeout al obtener tipos de ataque, usando fallback");
                return _fallback;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener tipos de ataque, usando fallback");
                return _fallback;
            }
        }

        // ────────────────────────────────────────────────────────
        // GET /benchmark
        // Metadatos de los 10 casos (sin prompts)
        // ────────────────────────────────────────────────────────

        public async Task<IEnumerable<BenchmarkMetadata>> ObtenerBenchmarkAsync()
        {
            try
            {
                var client = _httpClientFactory.CreateClient("FastAPI");
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var response = await client.GetAsync("/benchmark", cts.Token);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("Error {Code} al obtener metadatos benchmark",
                        (int)response.StatusCode);
                    return Enumerable.Empty<BenchmarkMetadata>();
                }

                var json = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<List<BenchmarkMetadata>>(json, _jsonOptions)
                       ?? new List<BenchmarkMetadata>();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener metadatos benchmark");
                return Enumerable.Empty<BenchmarkMetadata>();
            }
        }

        // ────────────────────────────────────────────────────────
        // POST /atacar — ataque individual
        // ────────────────────────────────────────────────────────

        public async Task<AtaqueResultado?> LanzarAtaqueAsync(
            string tipoAtaque,
            string? promptPersonalizado,
            int proyectoId,
            string? modeloAuditado = null)
        {
            try
            {
                _logger.LogInformation(
                    "Lanzando ataque {Tipo} en proyecto {Id} (modelo: {Modelo})",
                    tipoAtaque, proyectoId, modeloAuditado ?? "defecto");

                var client = _httpClientFactory.CreateClient("FastAPI");

                var body = new Dictionary<string, object?>
                {
                    ["tipo_ataque"] = tipoAtaque,
                    ["prompt_personalizado"] = string.IsNullOrWhiteSpace(promptPersonalizado)
                                                ? null : (object?)promptPersonalizado,
                    ["proyecto_id"] = proyectoId,
                    ["modelo_auditado"] = string.IsNullOrWhiteSpace(modeloAuditado)
                                                ? null : (object?)modeloAuditado,
                };

                var content = new StringContent(
                    JsonSerializer.Serialize(body, _jsonOptions),
                    Encoding.UTF8, "application/json");

                using var cts = new CancellationTokenSource(TimeoutAtaque);
                var response = await client.PostAsync("/atacar", content, cts.Token);

                if (!response.IsSuccessStatusCode)
                {
                    var err = await response.Content.ReadAsStringAsync();
                    _logger.LogError("Error {Code} al llamar /atacar: {Body}",
                        (int)response.StatusCode, err);
                    return null;
                }

                var json = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<AtaqueResultado>(json, _jsonOptions);
            }
            catch (TaskCanceledException)
            {
                _logger.LogError("Timeout ({Min} min) al lanzar ataque {Tipo}",
                    TimeoutAtaque.TotalMinutes, tipoAtaque);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inesperado al lanzar ataque {Tipo}", tipoAtaque);
                return null;
            }
        }

        // ────────────────────────────────────────────────────────
        // POST /auditar/batch — benchmark completo o subconjunto
        // ────────────────────────────────────────────────────────

        public async Task<ResultadoBatch?> LanzarBatchAsync(
            int proyectoId,
            string? modeloAuditado = null,
            List<string>? tiposAtaque = null)   // null → los 10 del benchmark
        {
            try
            {
                _logger.LogInformation(
                    "Lanzando batch en proyecto {Id} (modelo: {Modelo}, tipos: {Tipos})",
                    proyectoId, modeloAuditado ?? "defecto",
                    tiposAtaque is null ? "todos" : string.Join(",", tiposAtaque));

                var client = _httpClientFactory.CreateClient("FastAPI");

                var body = new Dictionary<string, object?>
                {
                    ["proyecto_id"] = proyectoId,
                    ["tipos_ataque"] = tiposAtaque ?? new List<string>(),
                    ["modelo_auditado"] = string.IsNullOrWhiteSpace(modeloAuditado)
                                          ? null : (object?)modeloAuditado,
                };

                var content = new StringContent(
                    JsonSerializer.Serialize(body, _jsonOptions),
                    Encoding.UTF8, "application/json");

                using var cts = new CancellationTokenSource(TimeoutBatch);
                var response = await client.PostAsync("/auditar/batch", content, cts.Token);

                if (!response.IsSuccessStatusCode)
                {
                    var err = await response.Content.ReadAsStringAsync();
                    _logger.LogError("Error {Code} en /auditar/batch: {Body}",
                        (int)response.StatusCode, err);
                    return null;
                }

                var json = await response.Content.ReadAsStringAsync();
                var resultado = JsonSerializer.Deserialize<ResultadoBatch>(json, _jsonOptions);

                _logger.LogInformation(
                    "Batch completado: {V}/{T} vulnerables ({Tasa}%)",
                    resultado?.TotalVulnerables, resultado?.TotalAtaques,
                    resultado?.TasaVulnerabilidad);

                return resultado;
            }
            catch (TaskCanceledException)
            {
                _logger.LogError("Timeout ({Min} min) en batch benchmark",
                    TimeoutBatch.TotalMinutes);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inesperado en batch benchmark");
                return null;
            }
        }

        // ────────────────────────────────────────────────────────
        // GET /auditorias — historial completo
        // ────────────────────────────────────────────────────────

        public async Task<IEnumerable<AtaqueResultado>> GetAuditoriasAsync()
        {
            try
            {
                var client = _httpClientFactory.CreateClient("FastAPI");
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                var response = await client.GetAsync("/auditorias", cts.Token);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("Error {Code} al obtener auditorías",
                        (int)response.StatusCode);
                    return Enumerable.Empty<AtaqueResultado>();
                }

                var json = await response.Content.ReadAsStringAsync();
                var resultado = JsonSerializer.Deserialize<List<AtaqueResultado>>(json, _jsonOptions);

                _logger.LogInformation("Historial: {Count} ataques obtenidos",
                    resultado?.Count ?? 0);

                return resultado ?? new List<AtaqueResultado>();
            }
            catch (TaskCanceledException)
            {
                _logger.LogWarning("Timeout al obtener historial de auditorías");
                return Enumerable.Empty<AtaqueResultado>();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener historial de auditorías");
                return Enumerable.Empty<AtaqueResultado>();
            }
        }

        // ────────────────────────────────────────────────────────
        // GET /modelos — lista de modelos disponibles en Ollama
        // ────────────────────────────────────────────────────────

        public async Task<IEnumerable<ModeloInfo>> ObtenerModelosAsync()
        {
            try
            {
                var client = _httpClientFactory.CreateClient("FastAPI");
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var response = await client.GetAsync("/modelos", cts.Token);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("Error {Code} al obtener modelos",
                        (int)response.StatusCode);
                    return Enumerable.Empty<ModeloInfo>();
                }

                var json = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<List<ModeloInfo>>(json, _jsonOptions)
                       ?? new List<ModeloInfo>();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener modelos disponibles");
                return Enumerable.Empty<ModeloInfo>();
            }
        }
    }
}