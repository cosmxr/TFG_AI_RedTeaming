// ============================================================
// IApiService.cs — Contrato del servicio que llama a FastAPI
// Los controladores C# dependen de esta interfaz, nunca
// de la implementación concreta directamente.
// ============================================================
namespace TFG_Portal.Services
{
    /// <summary>
    /// Define las operaciones disponibles contra la API FastAPI de Python.
    /// </summary>
    public interface IApiService
    {
        /// <summary>Comprueba si la API de Python está activa.</summary>
        Task<bool> GetEstadoAsync();

        /// <summary>Lanza un ataque enviando el tipo al endpoint /atacar.</summary>
        Task<AtaqueResultado?> LanzarAtaqueAsync(string tipoAtaque, string? promptPersonalizado);

        /// <summary>Obtiene el historial completo de ataques desde la API.</summary>
        Task<IEnumerable<AtaqueResultado>> GetAuditoriasAsync();
    }                                                             // ← cierre de IApiService

    /// <summary>
    /// DTO con el resultado devuelto por el endpoint POST /atacar
    /// </summary>
    public class AtaqueResultado
    {
        public int Id { get; set; }
        public string TipoAtaque { get; set; } = string.Empty;
        public string PromptEnviado { get; set; } = string.Empty;
        public string RespuestaIa { get; set; } = string.Empty;
        public bool FueVulnerable { get; set; }
        public DateTime FechaCreacion { get; set; }
    }                                                             
}                                                               