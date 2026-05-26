// ============================================================
// IApiService.cs — Interfaz del servicio de comunicación API
// AI Red Teaming Platform - TFG Ingeniería Informática
// v6.0 — benchmark plano, sin nivel_prompt
// ============================================================

using TFG_Portal.Models;

namespace TFG_Portal.Services
{
    public interface IApiService
    {
        // ── Estado ──────────────────────────────────────────
        Task<bool> GetEstadoAsync();

        // ── Catálogo ────────────────────────────────────────
        Task<TiposAtaqueResponse> ObtenerTiposAtaqueAsync();
        Task<IEnumerable<BenchmarkMetadata>> ObtenerBenchmarkAsync();
        Task<IEnumerable<ModeloInfo>> ObtenerModelosAsync();

        // ── Ataques ─────────────────────────────────────────
        Task<AtaqueResultado?> LanzarAtaqueAsync(
            string tipoAtaque,
            string? promptPersonalizado,
            int proyectoId,
            string? modeloAuditado = null);

        Task<ResultadoBatch?> LanzarBatchAsync(
            int proyectoId,
            string? modeloAuditado = null,
            List<string>? tiposAtaque = null);

        // ── Historial ───────────────────────────────────────
        Task<IEnumerable<AtaqueResultado>> GetAuditoriasAsync();
    }
}