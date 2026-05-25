// ============================================================
// ApiService.cs — Servicio que se comunica con la API FastAPI
// AI Red Teaming Platform - TFG Ingeniería Informática
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

        // Timeout para operaciones largas (ataques con 3 niveles de escalada)
        // 3 niveles × ~3 min/nivel + margen = 12 min
        private static readonly TimeSpan TimeoutAtaque = TimeSpan.FromMinutes(12);

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

        // --------------------------------------------------------
        // GET /estado
        // --------------------------------------------------------
        public async Task<bool> GetEstadoAsync()
        {
            try
            {
                var client = _httpClientFactory.CreateClient("FastAPI");
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var response = await client.GetAsync("/estado", cts.Token);
                var estaActiva = response.IsSuccessStatusCode;
                _logger.LogInformation("Estado API FastAPI: {Estado}",
                    estaActiva ? "ACTIVA" : "INACTIVA");
                return estaActiva;
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

        // --------------------------------------------------------
        // GET /tipos_ataque
        // --------------------------------------------------------
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

                if (resultado == null || !resultado.Todos.Any())
                {
                    _logger.LogWarning("Respuesta vacía de /tipos_ataque, usando fallback");
                    return _fallback;
                }

                _logger.LogInformation(
                    "Tipos de ataque obtenidos: {Clasico} clásicos, {Ai} AI red team",
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

        // --------------------------------------------------------
        // POST /atacar
        // FIX 1: timeout largo (12 min) para aguantar 3 niveles de escalada
        // FIX 2: se acepta y envía modelo_auditado
        // FIX 3: log de timeout corregido (eliminado "CSRF" hardcodeado)
        // --------------------------------------------------------
        public async Task<AtaqueResultado?> LanzarAtaqueAsync(
            string tipoAtaque,
            string? promptPersonalizado,
            int proyectoId,
            string? modeloAuditado = null)   // FIX 2: nuevo parámetro opcional
        {
            try
            {
                _logger.LogInformation(
                    "Lanzando ataque {Tipo} en proyecto {Id} (modelo: {Modelo})",
                    tipoAtaque, proyectoId, modeloAuditado ?? "defecto");

                var client = _httpClientFactory.CreateClient("FastAPI");

                var requestBody = new Dictionary<string, object?>
                {
                    ["tipo_ataque"] = tipoAtaque,
                    ["prompt_personalizado"] = string.IsNullOrWhiteSpace(promptPersonalizado)
                                                ? null
                                                : (object?)promptPersonalizado,
                    ["proyecto_id"] = proyectoId,
                    ["modelo_auditado"] = string.IsNullOrWhiteSpace(modeloAuditado)
                                                ? null
                                                : (object?)modeloAuditado   // FIX 2
                };

                var jsonBody = JsonSerializer.Serialize(requestBody, _jsonOptions);
                var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");

                // FIX 1: timeout explícito para operaciones largas
                using var cts = new CancellationTokenSource(TimeoutAtaque);
                var response = await client.PostAsync("/atacar", content, cts.Token);

                if (!response.IsSuccessStatusCode)
                {
                    var errorBody = await response.Content.ReadAsStringAsync();
                    _logger.LogError("Error {Code} al llamar /atacar: {Body}",
                        (int)response.StatusCode, errorBody);
                    return null;
                }

                var responseJson = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<AtaqueResultado>(responseJson, _jsonOptions);
            }
            catch (TaskCanceledException)
            {
                // FIX 3: eliminado "CSRF" hardcodeado
                _logger.LogError(
                    "Timeout ({Min} min) al lanzar ataque {Tipo}",
                    TimeoutAtaque.TotalMinutes, tipoAtaque);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inesperado al lanzar ataque {Tipo}", tipoAtaque);
                return null;
            }
        }

        // --------------------------------------------------------
        // GET /auditorias
        // FIX 4: añadido timeout de 30s
        // --------------------------------------------------------
        public async Task<IEnumerable<AtaqueResultado>> GetAuditoriasAsync()
        {
            try
            {
                var client = _httpClientFactory.CreateClient("FastAPI");

                // FIX 4: timeout razonable para una consulta de historial
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

                _logger.LogInformation("Se obtuvieron {Count} ataques del historial",
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
    }
}