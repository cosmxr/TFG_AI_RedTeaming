// ============================================================
// DatabaseService.cs — Acceso directo a SQL Server con Dapper
// AI Red Teaming Platform - TFG Ingeniería Informática
// ============================================================

using Dapper;
using Microsoft.Data.SqlClient;
using TFG_Portal.Models;

namespace TFG_Portal.Services
{
    public class DatabaseService : IDatabaseService
    {
        private readonly string _connectionString;
        private readonly ILogger<DatabaseService> _logger;

        public DatabaseService(IConfiguration configuration,
                                ILogger<DatabaseService> logger)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection")
                ?? throw new InvalidOperationException(
                    "No se encontró la cadena de conexión 'DefaultConnection'");
            _logger = logger;
        }

        // --------------------------------------------------------
        // Estadísticas para el Dashboard
        // --------------------------------------------------------

        public async Task<int> GetTotalAuditoriasAsync()
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                var total = await conn.QuerySingleOrDefaultAsync<int>(
                    "SELECT COUNT(*) FROM Auditorias");
                _logger.LogDebug("Total auditorías: {Total}", total);
                return total;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener total de auditorías");
                return 0;
            }
        }

        public async Task<int> GetTotalAtaquesAsync()
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                var total = await conn.QuerySingleOrDefaultAsync<int>(
                    "SELECT COUNT(*) FROM Ataques");
                _logger.LogDebug("Total ataques: {Total}", total);
                return total;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener total de ataques");
                return 0;
            }
        }

        public async Task<double> GetPorcentajeVulnerablesAsync()
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                const string sql = @"
                    SELECT ISNULL(
                        CAST(SUM(CASE WHEN fue_vulnerable = 1 THEN 1 ELSE 0 END) AS FLOAT)
                        / NULLIF(CAST(COUNT(*) AS FLOAT), 0) * 100
                    , 0.0)
                    FROM Ataques";

                var porcentaje = await conn.QuerySingleOrDefaultAsync<double>(sql);
                var resultado = Math.Round(porcentaje, 1);
                _logger.LogDebug("Porcentaje vulnerables: {Porcentaje}%", resultado);
                return resultado;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al calcular porcentaje de vulnerables");
                return 0.0;
            }
        }

        public async Task<int> GetTiposAtaqueDistintosAsync()
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                var total = await conn.QuerySingleOrDefaultAsync<int>(
                    "SELECT COUNT(DISTINCT tipo_ataque) FROM Ataques");
                _logger.LogDebug("Tipos de ataque distintos: {Total}", total);
                return total;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener tipos de ataque distintos");
                return 0;
            }
        }

        // --------------------------------------------------------
        // Datos para gráficos
        // --------------------------------------------------------

        public async Task<IEnumerable<AtaquesPorTipo>> GetAtaquesPorTipoAsync()
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                const string sql = @"
                    SELECT
                        tipo_ataque AS TipoAtaque,
                        COUNT(*)    AS Total
                    FROM Ataques
                    GROUP BY tipo_ataque
                    ORDER BY Total DESC";

                return await conn.QueryAsync<AtaquesPorTipo>(sql);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener ataques por tipo");
                return Enumerable.Empty<AtaquesPorTipo>();
            }
        }

        public async Task<IEnumerable<AtaquesPorDia>> GetAtaquesPorDiaAsync()
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                const string sql = @"
                    SELECT
                        FORMAT(CONVERT(date, fecha), 'dd/MM') AS Fecha,
                        COUNT(*) AS Total
                    FROM Ataques
                    WHERE fecha >= DATEADD(day, -7, GETDATE())
                    GROUP BY CONVERT(date, fecha)
                    ORDER BY CONVERT(date, fecha) ASC";

                return await conn.QueryAsync<AtaquesPorDia>(sql);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener ataques por día");
                return Enumerable.Empty<AtaquesPorDia>();
            }
        }

        // --------------------------------------------------------
        // Tablas
        // --------------------------------------------------------

        public async Task<IEnumerable<AuditoriaResumen>> GetUltimasAuditoriasAsync(int cantidad = 5)
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                const string sql = @"
                    SELECT TOP(@Cantidad)
                        a.id             AS Id,
                        a.modelo_ia      AS ModeloIa,
                        a.descripcion    AS Descripcion,
                        a.fecha_inicio   AS FechaCreacion,
                        COUNT(at.id)     AS TotalAtaques,
                        SUM(CASE WHEN at.fue_vulnerable = 1 THEN 1 ELSE 0 END)
                                         AS AtaquesVulnerables
                    FROM Auditorias a
                    LEFT JOIN Ataques at ON at.auditoria_id = a.id
                    GROUP BY a.id, a.modelo_ia, a.descripcion, a.fecha_inicio
                    ORDER BY a.fecha_inicio DESC";

                return await conn.QueryAsync<AuditoriaResumen>(sql, new { Cantidad = cantidad });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener últimas auditorías");
                return Enumerable.Empty<AuditoriaResumen>();
            }
        }

        public async Task<IEnumerable<AtaqueListItem>> GetTodosAtaquesAsync()
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                const string sql = @"
                    SELECT
                        at.id                        AS Id,
                        at.tipo_ataque               AS TipoAtaque,
                        LEFT(at.prompt_enviado, 100) AS PromptFragmento,
                        at.fue_vulnerable            AS FueVulnerable,
                        at.fecha                     AS FechaCreacion,
                        a.modelo_ia                  AS ModeloIa
                    FROM Ataques at
                    INNER JOIN Auditorias a ON a.id = at.auditoria_id
                    ORDER BY at.fecha DESC";

                var resultados = await conn.QueryAsync<AtaqueListItem>(sql);
                _logger.LogDebug("Se cargaron {Count} ataques para el historial",
                    resultados.Count());
                return resultados;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener todos los ataques");
                return Enumerable.Empty<AtaqueListItem>();
            }
        }

        public async Task<AtaqueDetalle?> GetAtaqueDetalleAsync(int id)
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                const string sql = @"
                    SELECT
                        at.id               AS Id,
                        at.auditoria_id     AS AuditoriaId,
                        at.tipo_ataque      AS TipoAtaque,
                        at.prompt_enviado   AS PromptEnviado,
                        at.respuesta_ia     AS RespuestaIa,
                        at.fue_vulnerable   AS FueVulnerable,
                        at.fecha            AS FechaCreacion,
                        a.modelo_ia         AS ModeloIa,
                        a.descripcion       AS AuditoriaDescripcion,
                        a.fecha_inicio    AS AuditoriaFechaCreacion
                    FROM Ataques at
                    INNER JOIN Auditorias a ON a.id = at.auditoria_id
                    WHERE at.id = @Id";

                var resultado = await conn.QuerySingleOrDefaultAsync<AtaqueDetalle>(
                    sql, new { Id = id });

                if (resultado is null)
                    _logger.LogWarning("Ataque con ID {Id} no encontrado en la BD", id);

                return resultado;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener detalle del ataque ID: {Id}", id);
                return null;
            }
        }
    }
}