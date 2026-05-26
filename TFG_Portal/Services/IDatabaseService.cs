// ============================================================
// IDatabaseService.cs — Interfaz del servicio de BD
// AI Red Teaming Platform - TFG Ingeniería Informática
// v6.0 — benchmark plano, sin nivel_prompt
// ============================================================

using TFG_Portal.Models;

namespace TFG_Portal.Services
{
    public interface IDatabaseService
    {
        // ── Proyectos ────────────────────────────────────────
        Task<IEnumerable<ProyectoResumen>> GetAllProyectosAsync();
        Task<Proyecto?> GetProyectoByIdAsync(int id);
        Task<int> CreateProyectoAsync(
                                               string nombre,
                                               string? descripcion,
                                               string? modeloIa);

        // ── Estadísticas por proyecto ────────────────────────
        Task<int> GetTotalAuditoriasAsync(int proyectoId);
        Task<int> GetTotalAtaquesAsync(int proyectoId);
        Task<double> GetPorcentajeVulnerablesAsync(int proyectoId);
        Task<int> GetTiposAtaqueDistintosAsync(int proyectoId);

        // ── Gráficos ─────────────────────────────────────────
        Task<IEnumerable<AtaquesPorTipo>> GetAtaquesPorTipoAsync(int proyectoId);
        Task<IEnumerable<AtaquesPorDia>> GetAtaquesPorDiaAsync(int proyectoId);
        Task<IEnumerable<AtaqueSeveridadResumen>> GetAtaquesPorSeveridadAsync(int proyectoId);

        // ── Auditorías ───────────────────────────────────────
        Task<ResumenAuditoria?> GetResumenAuditoriaAsync(int auditoriaId);
        Task<BenchmarkAuditoriaResult?> GetBenchmarkResultAsync(int auditoriaId);
        Task<IEnumerable<AuditoriaResumen>> GetUltimasAuditoriasAsync(
                                                 int proyectoId,
                                                 int cantidad = 5);

        // ── Ataques ──────────────────────────────────────────
        Task<IEnumerable<AtaqueListItem>> GetTodosAtaquesAsync(int proyectoId);
        Task<AtaqueDetalle?> GetAtaqueDetalleAsync(int id);

        // ── Comparativa y ranking ────────────────────────────
        Task<IEnumerable<ComparativaModelos>> GetComparativaModelosAsync(int proyectoId);
        Task<IEnumerable<RobustezItem>> GetRankingRobustezAsync(int proyectoId);
    }
}