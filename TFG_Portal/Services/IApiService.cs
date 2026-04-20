// ============================================================
// IApiService.cs
// ============================================================
using System.Text.Json.Serialization;

namespace TFG_Portal.Services
{
    public interface IApiService
    {
        Task<bool> GetEstadoAsync();
        Task<AtaqueResultado?> LanzarAtaqueAsync(string tipoAtaque,
                                                  string? promptPersonalizado,
                                                  int proyectoId);
        Task<IEnumerable<AtaqueResultado>> GetAuditoriasAsync();
    }

    public class AtaqueResultado
    {
        [JsonPropertyName("auditoria_id")]
        public int Id { get; set; }

        [JsonPropertyName("ataque_id")]
        public int AtaqueId { get; set; }

        [JsonPropertyName("tipo_ataque")]
        public string TipoAtaque { get; set; } = string.Empty;

        [JsonPropertyName("prompt_enviado")]
        public string PromptEnviado { get; set; } = string.Empty;

        [JsonPropertyName("respuesta_ia")]
        public string RespuestaIa { get; set; } = string.Empty;

        [JsonPropertyName("fue_vulnerable")]
        public bool FueVulnerable { get; set; }

        [JsonPropertyName("fecha_creacion")]
        public DateTime FechaCreacion { get; set; }
    }
}