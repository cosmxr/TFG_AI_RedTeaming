// ============================================================
// ApiService.cs — Servicio que se comunica con la API FastAPI
// AI Red Teaming Platform - TFG Ingeniería Informática
// ============================================================

using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TFG_Portal.Services
{
    public class ApiService : IApiService
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<ApiService> _logger;
        private readonly JsonSerializerOptions _jsonOptions;

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
        // GET /estado — Comprueba si la API de Python está activa
        // --------------------------------------------------------
        public async Task<bool> GetEstadoAsync()
        {
            try
            {
                _logger.LogDebug("Comprobando estado de la API FastAPI...");
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
                _logger.LogWarning("Timeout al comprobar estado de la API: {Mensaje}", ex.Message);
                return false;
            }
            catch (HttpRequestException ex)
            {
                _logger.LogWarning("La API FastAPI no está disponible: {Mensaje}", ex.Message);
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inesperado al comprobar estado de la API");
                return false;
            }
        }

        // --------------------------------------------------------
        // POST /atacar — Lanza un ataque y devuelve el resultado
        // --------------------------------------------------------
        public async Task<AtaqueResultado?> LanzarAtaqueAsync(string tipoAtaque,
                                                               string? promptPersonalizado)
        {
            try
            {
                _logger.LogInformation("Lanzando ataque de tipo: {TipoAtaque}", tipoAtaque);
                var client = _httpClientFactory.CreateClient("FastAPI");

                var requestBody = new Dictionary<string, object?>
                {
                    ["tipo_ataque"] = tipoAtaque,
                    ["prompt_personalizado"] = string.IsNullOrWhiteSpace(promptPersonalizado)
                        ? null
                        : (object?)promptPersonalizado
                };

                var jsonBody = JsonSerializer.Serialize(requestBody, _jsonOptions);
                var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
                _logger.LogDebug("JSON enviado a /atacar: {Json}", jsonBody);

                var response = await client.PostAsync("/atacar", content);

                if (!response.IsSuccessStatusCode)
                {
                    var errorBody = await response.Content.ReadAsStringAsync();
                    _logger.LogError("Error {StatusCode} al llamar /atacar: {Body}",
                        (int)response.StatusCode, errorBody);
                    return null;
                }

                var responseJson = await response.Content.ReadAsStringAsync();
                _logger.LogDebug("Respuesta de /atacar: {Json}", responseJson);

                var resultado = JsonSerializer.Deserialize<AtaqueResultado>(responseJson, _jsonOptions);
                _logger.LogInformation("Ataque completado. ID: {Id}, Vulnerable: {Vulnerable}",
                    resultado?.Id, resultado?.FueVulnerable);

                return resultado;
            }
            catch (TaskCanceledException)
            {
                _logger.LogError("Timeout al lanzar ataque {TipoAtaque}: WhiteRabbitNeo tardó demasiado",
                    tipoAtaque);
                return null;
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "Error de red al lanzar ataque {TipoAtaque}", tipoAtaque);
                return null;
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "Error al deserializar respuesta de /atacar");
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inesperado al lanzar ataque {TipoAtaque}", tipoAtaque);
                return null;
            }
        }

        // --------------------------------------------------------
        // GET /auditorias — Historial completo. Nunca devuelve null
        // --------------------------------------------------------
        public async Task<IEnumerable<AtaqueResultado>> GetAuditoriasAsync()
        {
            try
            {
                _logger.LogDebug("Obteniendo historial de auditorías desde la API...");
                var client = _httpClientFactory.CreateClient("FastAPI");
                var response = await client.GetAsync("/auditorias");

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning("Error {StatusCode} al obtener auditorías",
                        (int)response.StatusCode);
                    return Enumerable.Empty<AtaqueResultado>();
                }

                var responseJson = await response.Content.ReadAsStringAsync();
                var resultados = JsonSerializer.Deserialize<List<AtaqueResultado>>(
                    responseJson, _jsonOptions);

                _logger.LogInformation("Se obtuvieron {Count} ataques del historial",
                    resultados?.Count);

                return resultados ?? new List<AtaqueResultado>();
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "Error de red al obtener historial de auditorías");
                return Enumerable.Empty<AtaqueResultado>();
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "Error al deserializar respuesta de /auditorias");
                return Enumerable.Empty<AtaqueResultado>();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error inesperado al obtener auditorías");
                return Enumerable.Empty<AtaqueResultado>();
            }
        }
    }
}