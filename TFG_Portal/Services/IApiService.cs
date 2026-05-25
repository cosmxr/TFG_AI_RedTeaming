// ============================================================
// IApiService.cs
// AI Red Teaming Platform - TFG Ingeniería Informática
// ============================================================

using System.Text.Json.Serialization;
using TFG_Portal.Models;

namespace TFG_Portal.Services
{
    public interface IApiService
    {
        Task<bool> GetEstadoAsync();

        Task<TiposAtaqueResponse> ObtenerTiposAtaqueAsync();

        Task<AtaqueResultado?> LanzarAtaqueAsync(
            string tipoAtaque,
            string? promptPersonalizado,
            int proyectoId,
            string? modeloAuditado = null);

        Task<IEnumerable<AtaqueResultado>> GetAuditoriasAsync();
    }

    public class AtaqueResultado
    {
        [JsonPropertyName("auditoria_id")]
        public int AuditoriaId { get; set; }

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

        [JsonPropertyName("severidad")]
        public string? Severidad { get; set; }

        [JsonPropertyName("tipo_payload")]
        public string? TipoPayload { get; set; }

        [JsonPropertyName("justificacion")]
        public string? Justificacion { get; set; }

        [JsonPropertyName("recomendacion")]
        public string? Recomendacion { get; set; }

        [JsonPropertyName("tiempo_respuesta")]
        public int? TiempoRespuesta { get; set; }

        [JsonPropertyName("iteraciones")]
        public int Iteraciones { get; set; } = 1;

        [JsonPropertyName("nivel_prompt")]
        public int? NivelPrompt { get; set; }

        [JsonPropertyName("modelo_auditado")]
        public string? ModeloAuditado { get; set; }

        [JsonPropertyName("fecha")]
        public DateTime? FechaCreacion { get; set; }

        // ── Propiedades calculadas en cliente ────────────────
        // Usado en RedirectToAction("Detalle", new { id = resultado.Id })
        public int Id => AuditoriaId;

        public string Categoria =>
            CategoriasAtaque.ObtenerCategoria(TipoAtaque);

        public bool EsAiRedteam =>
            Categoria == "ai_redteam";
    }
}