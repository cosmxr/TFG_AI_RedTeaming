// ============================================================
// IDatabaseService.cs — Contrato del servicio de base de datos
// ============================================================
using TFG_Portal.Models;

namespace TFG_Portal.Services
{
    public interface IDatabaseService
    {
        // --- Proyectos ---
        Task<IEnumerable<ProyectoResumen>> GetAllProyectosAsync();
        Task<Proyecto?> GetProyectoByIdAsync(int id);
        Task<int> CreateProyectoAsync(string nombre, string? descripcion, string? modeloIa);

        // --- Estadísticas filtradas por proyecto ---
        Task<int> GetTotalAuditoriasAsync(int proyectoId);
        Task<int> GetTotalAtaquesAsync(int proyectoId);
        Task<double> GetPorcentajeVulnerablesAsync(int proyectoId);
        Task<int> GetTiposAtaqueDistintosAsync(int proyectoId);

        // --- Gráficos filtrados por proyecto ---
        Task<IEnumerable<AtaquesPorTipo>> GetAtaquesPorTipoAsync(int proyectoId);
        Task<IEnumerable<AtaquesPorDia>> GetAtaquesPorDiaAsync(int proyectoId);
        Task<IEnumerable<AtaqueSeveridadResumen>> GetAtaquesPorSeveridadAsync(int proyectoId);
        Task<ResumenAuditoria?> GetResumenAuditoriaAsync(int auditoriaId);

        // --- Tablas filtradas por proyecto ---
        Task<IEnumerable<AuditoriaResumen>> GetUltimasAuditoriasAsync(int proyectoId, int cantidad = 5);
        Task<IEnumerable<AtaqueListItem>> GetTodosAtaquesAsync(int proyectoId);
        Task<AtaqueDetalle?> GetAtaqueDetalleAsync(int id);
    }
}