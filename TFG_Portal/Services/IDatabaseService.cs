// ============================================================
// IDatabaseService.cs — Contrato del servicio de base de datos
// Acceso directo a SQL Server con Dapper (sin Entity Framework)
// ============================================================
using TFG_Portal.Models;

namespace TFG_Portal.Services
{
    /// <summary>
    /// Define las consultas directas a SQL Server LocalDB.
    /// La implementación real está en DatabaseService.cs.
    /// </summary>
    public interface IDatabaseService
    {
        // --- Estadísticas para el Dashboard ---
        Task<int> GetTotalAuditoriasAsync();
        Task<int> GetTotalAtaquesAsync();
        Task<double> GetPorcentajeVulnerablesAsync();
        Task<int> GetTiposAtaqueDistintosAsync();

        // --- Datos para gráficos ---
        Task<IEnumerable<AtaquesPorTipo>> GetAtaquesPorTipoAsync();
        Task<IEnumerable<AtaquesPorDia>> GetAtaquesPorDiaAsync();

        // --- Tablas ---
        Task<IEnumerable<AuditoriaResumen>> GetUltimasAuditoriasAsync(int cantidad = 5);
        Task<IEnumerable<AtaqueListItem>> GetTodosAtaquesAsync();
        Task<AtaqueDetalle?> GetAtaqueDetalleAsync(int id);
    }
}