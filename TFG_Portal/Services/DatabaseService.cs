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
        // PROYECTOS
        // --------------------------------------------------------

        public async Task<IEnumerable<ProyectoResumen>> GetAllProyectosAsync()
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                const string sql = @"
                    SELECT
                        p.id             AS Id,
                        p.nombre         AS Nombre,
                        p.fecha_inicio   AS FechaInicio,
                        COUNT(DISTINCT a.id) AS TotalAuditorias
                    FROM Proyectos p
                    LEFT JOIN Auditorias a ON a.proyecto_id = p.id
                    GROUP BY p.id, p.nombre, p.fecha_inicio
                    ORDER BY p.fecha_inicio DESC";

                return await conn.QueryAsync<ProyectoResumen>(sql);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener lista de proyectos");
                return Enumerable.Empty<ProyectoResumen>();
            }
        }

        public async Task<Proyecto?> GetProyectoByIdAsync(int id)
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                const string sql = @"
                    SELECT
                        p.id             AS Id,
                        p.nombre         AS Nombre,
                        p.descripcion    AS Descripcion,
                        p.modelo_ia      AS ModeloIa,
                        p.fecha_inicio   AS FechaInicio,
                        p.activo         AS Activo,
                        COUNT(DISTINCT a.id)  AS TotalAuditorias,
                        COUNT(at.id)          AS TotalAtaques
                    FROM Proyectos p
                    LEFT JOIN Auditorias a  ON a.proyecto_id = p.id
                    LEFT JOIN Ataques at    ON at.auditoria_id = a.id
                    WHERE p.id = @Id
                    GROUP BY p.id, p.nombre, p.descripcion,
                             p.modelo_ia, p.fecha_inicio, p.activo";

                return await conn.QuerySingleOrDefaultAsync<Proyecto>(sql, new { Id = id });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener proyecto ID: {Id}", id);
                return null;
            }
        }

        public async Task<int> CreateProyectoAsync(string nombre, string? descripcion, string? modeloIa)
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                const string sql = @"
                    INSERT INTO Proyectos (nombre, descripcion, modelo_ia, fecha_inicio, activo)
                    VALUES (@Nombre, @Descripcion, @ModeloIa, GETDATE(), 1);
                    SELECT CAST(SCOPE_IDENTITY() AS INT);";

                var newId = await conn.QuerySingleAsync<int>(sql, new
                {
                    Nombre = nombre,
                    Descripcion = descripcion,
                    ModeloIa = modeloIa
                });

                _logger.LogInformation("Proyecto creado con ID: {Id}", newId);
                return newId;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al crear proyecto");
                return 0;
            }
        }

        // --------------------------------------------------------
        // ESTADÍSTICAS filtradas por proyecto
        // --------------------------------------------------------

        public async Task<int> GetTotalAuditoriasAsync(int proyectoId)
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                var total = await conn.QuerySingleOrDefaultAsync<int>(
                    "SELECT COUNT(*) FROM Auditorias WHERE proyecto_id = @ProyectoId",
                    new { ProyectoId = proyectoId });
                return total;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener total de auditorías");
                return 0;
            }
        }

        public async Task<int> GetTotalAtaquesAsync(int proyectoId)
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                const string sql = @"
                    SELECT COUNT(*)
                    FROM Ataques at
                    INNER JOIN Auditorias a ON a.id = at.auditoria_id
                    WHERE a.proyecto_id = @ProyectoId";

                return await conn.QuerySingleOrDefaultAsync<int>(sql,
                    new { ProyectoId = proyectoId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener total de ataques");
                return 0;
            }
        }

        public async Task<double> GetPorcentajeVulnerablesAsync(int proyectoId)
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                const string sql = @"
                    SELECT ISNULL(
                        CAST(SUM(CASE WHEN at.fue_vulnerable = 1 THEN 1 ELSE 0 END) AS FLOAT)
                        / NULLIF(CAST(COUNT(*) AS FLOAT), 0) * 100
                    , 0.0)
                    FROM Ataques at
                    INNER JOIN Auditorias a ON a.id = at.auditoria_id
                    WHERE a.proyecto_id = @ProyectoId";

                var porcentaje = await conn.QuerySingleOrDefaultAsync<double>(sql,
                    new { ProyectoId = proyectoId });
                return Math.Round(porcentaje, 1);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al calcular porcentaje de vulnerables");
                return 0.0;
            }
        }

        public async Task<int> GetTiposAtaqueDistintosAsync(int proyectoId)
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                const string sql = @"
                    SELECT COUNT(DISTINCT at.tipo_ataque)
                    FROM Ataques at
                    INNER JOIN Auditorias a ON a.id = at.auditoria_id
                    WHERE a.proyecto_id = @ProyectoId";

                return await conn.QuerySingleOrDefaultAsync<int>(sql,
                    new { ProyectoId = proyectoId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener tipos de ataque distintos");
                return 0;
            }
        }

        // --------------------------------------------------------
        // GRÁFICOS filtrados por proyecto
        // --------------------------------------------------------

        public async Task<IEnumerable<AtaquesPorTipo>> GetAtaquesPorTipoAsync(int proyectoId)
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                const string sql = @"
                    SELECT
                        at.tipo_ataque AS TipoAtaque,
                        COUNT(*)       AS Total
                    FROM Ataques at
                    INNER JOIN Auditorias a ON a.id = at.auditoria_id
                    WHERE a.proyecto_id = @ProyectoId
                    GROUP BY at.tipo_ataque
                    ORDER BY Total DESC";

                return await conn.QueryAsync<AtaquesPorTipo>(sql,
                    new { ProyectoId = proyectoId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener ataques por tipo");
                return Enumerable.Empty<AtaquesPorTipo>();
            }
        }

        public async Task<IEnumerable<AtaquesPorDia>> GetAtaquesPorDiaAsync(int proyectoId)
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                const string sql = @"
                    SELECT
                        FORMAT(CONVERT(date, at.fecha), 'dd/MM') AS Fecha,
                        COUNT(*) AS Total
                    FROM Ataques at
                    INNER JOIN Auditorias a ON a.id = at.auditoria_id
                    WHERE a.proyecto_id = @ProyectoId
                      AND at.fecha >= DATEADD(day, -7, GETDATE())
                    GROUP BY CONVERT(date, at.fecha)
                    ORDER BY CONVERT(date, at.fecha) ASC";

                return await conn.QueryAsync<AtaquesPorDia>(sql,
                    new { ProyectoId = proyectoId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener ataques por día");
                return Enumerable.Empty<AtaquesPorDia>();
            }
        }

        // --------------------------------------------------------
        // TABLAS filtradas por proyecto
        // --------------------------------------------------------

        public async Task<IEnumerable<AuditoriaResumen>> GetUltimasAuditoriasAsync(
            int proyectoId, int cantidad = 5)
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                const string sql = @"
                    SELECT TOP(@Cantidad)
                        a.id             AS Id,
                        a.proyecto_id    AS ProyectoId,
                        a.modelo_ia      AS ModeloIa,
                        a.descripcion    AS Descripcion,
                        a.fecha_inicio   AS FechaCreacion,
                        COUNT(at.id)     AS TotalAtaques,
                        SUM(CASE WHEN at.fue_vulnerable = 1 THEN 1 ELSE 0 END)
                                         AS AtaquesVulnerables
                    FROM Auditorias a
                    LEFT JOIN Ataques at ON at.auditoria_id = a.id
                    WHERE a.proyecto_id = @ProyectoId
                    GROUP BY a.id, a.proyecto_id, a.modelo_ia,
                             a.descripcion, a.fecha_inicio
                    ORDER BY a.fecha_inicio DESC";

                return await conn.QueryAsync<AuditoriaResumen>(sql,
                    new { ProyectoId = proyectoId, Cantidad = cantidad });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener últimas auditorías");
                return Enumerable.Empty<AuditoriaResumen>();
            }
        }

        public async Task<IEnumerable<AtaqueListItem>> GetTodosAtaquesAsync(int proyectoId)
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
                    WHERE a.proyecto_id = @ProyectoId
                    ORDER BY at.fecha DESC";

                var resultados = await conn.QueryAsync<AtaqueListItem>(sql,
                    new { ProyectoId = proyectoId });
                _logger.LogDebug("Se cargaron {Count} ataques", resultados.Count());
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
                        a.fecha_inicio      AS AuditoriaFechaCreacion
                    FROM Ataques at
                    INNER JOIN Auditorias a ON a.id = at.auditoria_id
                    WHERE at.id = @Id";

                var resultado = await conn.QuerySingleOrDefaultAsync<AtaqueDetalle>(
                    sql, new { Id = id });

                if (resultado is null)
                    _logger.LogWarning("Ataque con ID {Id} no encontrado", id);

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