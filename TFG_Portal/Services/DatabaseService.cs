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
                        p.id                   AS Id,
                        p.nombre               AS Nombre,
                        p.fecha_inicio         AS FechaInicio,
                        COUNT(DISTINCT a.id)   AS TotalAuditorias
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
                        p.id                   AS Id,
                        p.nombre               AS Nombre,
                        p.descripcion          AS Descripcion,
                        p.modelo_ia            AS ModeloIa,
                        p.fecha_inicio         AS FechaInicio,
                        p.activo               AS Activo,
                        COUNT(DISTINCT a.id)   AS TotalAuditorias,
                        COUNT(at.id)           AS TotalAtaques
                    FROM Proyectos p
                    LEFT JOIN Auditorias a ON a.proyecto_id = p.id
                    LEFT JOIN Ataques at   ON at.auditoria_id = a.id
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
                return await conn.QuerySingleOrDefaultAsync<int>(
                    "SELECT COUNT(*) FROM Auditorias WHERE proyecto_id = @ProyectoId",
                    new { ProyectoId = proyectoId });
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
                        FORMAT(CAST(at.fecha AS DATE), 'dd/MM') AS Fecha,
                        COUNT(*) AS Total
                    FROM Ataques at
                    INNER JOIN Auditorias a ON a.id = at.auditoria_id
                    WHERE a.proyecto_id = @ProyectoId
                      AND at.fecha >= DATEADD(DAY, -7, GETDATE())
                    GROUP BY CAST(at.fecha AS DATE)
                    ORDER BY CAST(at.fecha AS DATE) ASC";

                return await conn.QueryAsync<AtaquesPorDia>(sql,
                    new { ProyectoId = proyectoId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener ataques por día");
                return Enumerable.Empty<AtaquesPorDia>();
            }
        }

        // ── NUEVO FASE 1 ─────────────────────────────────────────

        public async Task<IEnumerable<AtaqueSeveridadResumen>> GetAtaquesPorSeveridadAsync(int proyectoId)
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                const string sql = @"
                    SELECT
                        at.severidad AS Severidad,
                        COUNT(*)     AS Total
                    FROM Ataques at
                    INNER JOIN Auditorias a ON a.id = at.auditoria_id
                    WHERE a.proyecto_id = @ProyectoId
                      AND at.fue_vulnerable = 1
                      AND at.severidad IS NOT NULL
                    GROUP BY at.severidad
                    ORDER BY Total DESC";

                return await conn.QueryAsync<AtaqueSeveridadResumen>(sql,
                    new { ProyectoId = proyectoId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener ataques por severidad");
                return Enumerable.Empty<AtaqueSeveridadResumen>();
            }
        }

        public async Task<ResumenAuditoria?> GetResumenAuditoriaAsync(int auditoriaId)
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                const string sql = @"
                    SELECT
                        au.id                                        AS AuditoriaId,
                        au.modelo_ia                                 AS ModeloIa,
                        COUNT(at.id)                                 AS TotalAtaques,
                        SUM(CASE WHEN at.fue_vulnerable = 1
                                 THEN 1 ELSE 0 END)                AS TotalVulnerables,
                        (
                            SELECT TOP 1 a2.severidad
                            FROM Ataques a2
                            WHERE a2.auditoria_id = au.id
                              AND a2.fue_vulnerable = 1
                              AND a2.severidad IS NOT NULL
                            GROUP BY a2.severidad
                            ORDER BY COUNT(*) DESC
                        )                                            AS SeveridadMasFrecuente,
                        (
                            SELECT TOP 1 a3.tipo_payload
                            FROM Ataques a3
                            WHERE a3.auditoria_id = au.id
                              AND a3.tipo_payload IS NOT NULL
                            GROUP BY a3.tipo_payload
                            ORDER BY COUNT(*) DESC
                        )                                            AS TipoPayloadMasFrecuente,
                        CAST(AVG(CAST(at.tiempo_respuesta AS FLOAT)) AS INT) AS TiempoMedioRespuesta,
                        MIN(at.fecha) AS FechaInicio,
                        MAX(at.fecha) AS FechaUltimoAtaque
                    FROM Auditorias au
                    LEFT JOIN Ataques at ON at.auditoria_id = au.id
                    WHERE au.id = @AuditoriaId
                    GROUP BY au.id, au.modelo_ia";

                return await conn.QuerySingleOrDefaultAsync<ResumenAuditoria>(sql,
                    new { AuditoriaId = auditoriaId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener resumen auditoría ID: {Id}", auditoriaId);
                return null;
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
                        SUM(CASE WHEN at.fue_vulnerable = 1
                                 THEN 1 ELSE 0 END) AS AtaquesVulnerables
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
                a.modelo_ia                  AS ModeloIa,
                at.severidad                 AS Severidad,
                at.tipo_payload              AS TipoPayload,
                at.nivel_prompt              AS NivelPrompt
            FROM Ataques at
            INNER JOIN Auditorias a ON a.id = at.auditoria_id
            WHERE a.proyecto_id = @ProyectoId
            ORDER BY at.fecha DESC";

                return await conn.QueryAsync<AtaqueListItem>(sql,
                    new { ProyectoId = proyectoId });
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
                at.id                   AS Id,
                at.auditoria_id         AS AuditoriaId,
                at.tipo_ataque          AS TipoAtaque,
                at.prompt_enviado       AS PromptEnviado,
                at.respuesta_ia         AS RespuestaIa,
                at.fue_vulnerable       AS FueVulnerable,
                at.fecha                AS FechaCreacion,
                at.severidad            AS Severidad,
                at.tipo_payload         AS TipoPayload,
                at.justificacion        AS Justificacion,
                at.recomendacion        AS Recomendacion,
                at.tiempo_respuesta     AS TiempoRespuesta,
                at.iteraciones          AS Iteraciones,
                at.nivel_prompt         AS NivelPrompt,
                a.modelo_ia             AS ModeloIa,
                a.descripcion           AS AuditoriaDescripcion,
                a.fecha_inicio        AS AuditoriaFechaCreacion
            FROM Ataques at
            INNER JOIN Auditorias a ON a.id = at.auditoria_id
            WHERE at.id = @Id";

                return await conn.QuerySingleOrDefaultAsync<AtaqueDetalle>(
                    sql, new { Id = id });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener detalle del ataque ID: {Id}", id);
                return null;
            }
        }

        // --------------------------------------------------------
        // COMPARATIVA MODELOS
        // --------------------------------------------------------

        public async Task<IEnumerable<ComparativaModelos>> GetComparativaModelosAsync(int proyectoId)
        {
            try
            {
                using var conn = new SqlConnection(_connectionString);
                const string sql = @"
                    SELECT
                        cm.id                 AS Id,
                        cm.proyecto_id        AS ProyectoId,
                        cm.modelo_ia          AS ModeloIa,
                        cm.tipo_ataque        AS TipoAtaque,
                        cm.total_ataques      AS TotalAtaques,
                        cm.total_vulnerables  AS TotalVulnerables,
                        cm.tasa_vulnerabilidad AS TasaVulnerabilidad,
                        cm.severidad_alta     AS SeveridadAlta,
                        cm.severidad_media    AS SeveridadMedia,
                        cm.severidad_baja     AS SeveridadBaja,
                        cm.tiempo_medio       AS TiempoMedio,
                        cm.tiempo_min         AS TiempoMin,
                        cm.tiempo_max         AS TiempoMax,
                        cm.fecha_calculo      AS FechaCalculo
                    FROM ComparativaModelos cm
                    WHERE cm.proyecto_id = @ProyectoId
                    ORDER BY cm.fecha_calculo DESC, cm.modelo_ia, cm.tipo_ataque";

                return await conn.QueryAsync<ComparativaModelos>(sql,
                    new { ProyectoId = proyectoId });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al obtener comparativa de modelos");
                return Enumerable.Empty<ComparativaModelos>();
            }
        }
    }
}