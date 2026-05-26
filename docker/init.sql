-- ============================================================
-- init.sql — TFG AI Red Teaming Platform
-- SQL Server — inicialización + migraciones idempotentes
-- v6.0: benchmark plano, sin nivel_prompt,
--       con benchmark_id y canary_detectado en Ataques
-- ============================================================

-- ── Crear base de datos ──────────────────────────────────────
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'TFG_RedTeaming')
BEGIN
    CREATE DATABASE TFG_RedTeaming;
END
GO

USE TFG_RedTeaming;
GO

-- ── Tabla: Proyectos ─────────────────────────────────────────
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name = 'Proyectos' AND xtype = 'U')
CREATE TABLE Proyectos (
    id           INT IDENTITY(1,1) PRIMARY KEY,
    nombre       NVARCHAR(200)  NOT NULL,
    descripcion  NVARCHAR(1000) NULL,
    modelo_ia    NVARCHAR(200)  NULL,
    fecha_inicio DATETIME       DEFAULT GETDATE(),
    activo       BIT            DEFAULT 1
);
GO

-- ── Tabla: Auditorias ────────────────────────────────────────
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name = 'Auditorias' AND xtype = 'U')
CREATE TABLE Auditorias (
    id           INT IDENTITY(1,1) PRIMARY KEY,
    proyecto_id  INT           NOT NULL REFERENCES Proyectos(id),
    modelo_ia    NVARCHAR(200) NOT NULL,
    descripcion  NVARCHAR(500) NULL,
    estado       NVARCHAR(50)  DEFAULT 'completada',
    fecha_inicio DATETIME      DEFAULT GETDATE()
);
GO

-- ── Tabla: Ataques ───────────────────────────────────────────
-- Creación inicial (instalaciones nuevas)
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name = 'Ataques' AND xtype = 'U')
CREATE TABLE Ataques (
    id               INT IDENTITY(1,1) PRIMARY KEY,
    auditoria_id     INT           NOT NULL REFERENCES Auditorias(id),
    tipo_ataque      NVARCHAR(50)  NOT NULL,
    -- Trazabilidad al caso benchmark (ej: "PI-01", "CL-02")
    benchmark_id     NVARCHAR(10)  NULL,
    prompt_enviado   NVARCHAR(MAX) NULL,
    respuesta_ia     NVARCHAR(MAX) NULL,
    fue_vulnerable   BIT           DEFAULT 0,
    -- True si el canary token apareció en la respuesta (detección determinista)
    canary_detectado BIT           DEFAULT 0,
    firewall_activo  BIT           DEFAULT 0,
    fecha            DATETIME      DEFAULT GETDATE(),
    severidad        NVARCHAR(20)  NULL,   -- 'Alta' | 'Media' | 'Baja'
    tipo_payload     NVARCHAR(20)  NULL,   -- 'funcional' | 'generico' | 'rechazo'
    justificacion    NVARCHAR(500) NULL,
    recomendacion    NVARCHAR(500) NULL,
    tiempo_respuesta INT           NULL    -- ms
);
GO

-- ── Migraciones idempotentes (instalaciones existentes) ──────
-- Añade benchmark_id si no existe
IF NOT EXISTS (
    SELECT 1 FROM sys.columns
    WHERE object_id = OBJECT_ID('Ataques') AND name = 'benchmark_id'
)
BEGIN
    ALTER TABLE Ataques ADD benchmark_id NVARCHAR(10) NULL;
    PRINT 'Columna benchmark_id añadida a Ataques.';
END
GO

-- Añade canary_detectado si no existe
IF NOT EXISTS (
    SELECT 1 FROM sys.columns
    WHERE object_id = OBJECT_ID('Ataques') AND name = 'canary_detectado'
)
BEGIN
    ALTER TABLE Ataques ADD canary_detectado BIT DEFAULT 0 NULL;
    PRINT 'Columna canary_detectado añadida a Ataques.';
END
GO

-- Elimina nivel_prompt si todavía existe (columna de versiones anteriores)
IF EXISTS (
    SELECT 1 FROM sys.columns
    WHERE object_id = OBJECT_ID('Ataques') AND name = 'nivel_prompt'
)
BEGIN
    ALTER TABLE Ataques DROP COLUMN nivel_prompt;
    PRINT 'Columna nivel_prompt eliminada de Ataques.';
END
GO

-- Elimina iteraciones si todavía existe
IF EXISTS (
    SELECT 1 FROM sys.columns
    WHERE object_id = OBJECT_ID('Ataques') AND name = 'iteraciones'
)
BEGIN
    ALTER TABLE Ataques DROP COLUMN iteraciones;
    PRINT 'Columna iteraciones eliminada de Ataques.';
END
GO

-- ── Tabla: ComparativaModelos ────────────────────────────────
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name = 'ComparativaModelos' AND xtype = 'U')
CREATE TABLE ComparativaModelos (
    id                  INT IDENTITY(1,1) PRIMARY KEY,
    proyecto_id         INT           NOT NULL REFERENCES Proyectos(id),
    modelo_ia           NVARCHAR(200) NOT NULL,
    tipo_ataque         NVARCHAR(50)  NOT NULL,
    total_ataques       INT           DEFAULT 0,
    total_vulnerables   INT           DEFAULT 0,
    tasa_vulnerabilidad FLOAT         DEFAULT 0,
    severidad_alta      INT           DEFAULT 0,
    severidad_media     INT           DEFAULT 0,
    severidad_baja      INT           DEFAULT 0,
    tiempo_medio        FLOAT         NULL,
    tiempo_min          INT           NULL,
    tiempo_max          INT           NULL,
    fecha_calculo       DATETIME      DEFAULT GETDATE()
);
GO

-- ── Índices para consultas frecuentes ───────────────────────
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_Ataques_AuditoriaId')
    CREATE INDEX IX_Ataques_AuditoriaId ON Ataques(auditoria_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_Ataques_TipoAtaque')
    CREATE INDEX IX_Ataques_TipoAtaque ON Ataques(tipo_ataque);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_Ataques_benchmark_id')
    CREATE INDEX IX_Ataques_benchmark_id ON Ataques(benchmark_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_Auditorias_ProyectoId')
    CREATE INDEX IX_Auditorias_ProyectoId ON Auditorias(proyecto_id);
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_ComparativaModelos_ProyectoId')
    CREATE INDEX IX_ComparativaModelos_ProyectoId
        ON ComparativaModelos(proyecto_id, modelo_ia, tipo_ataque);
GO

-- ── Vista: VW_ResumenBenchmark ───────────────────────────────
-- Resumen por auditoría con score ponderado (Alta=2, Media=1)
-- Útil para la vista de resultados y el ranking de robustez.
IF EXISTS (SELECT * FROM sys.views WHERE name = 'VW_ResumenBenchmark')
    DROP VIEW VW_ResumenBenchmark;
GO

CREATE VIEW VW_ResumenBenchmark AS
SELECT
    au.id                                                       AS AuditoriaId,
    au.proyecto_id                                              AS ProyectoId,
    au.modelo_ia                                                AS ModeloAuditado,
    au.fecha_inicio                                             AS FechaAuditoria,
    COUNT(at.id)                                                AS TotalCasos,
    SUM(CAST(at.fue_vulnerable AS INT))                         AS TotalVulnerables,
    SUM(CAST(at.canary_detectado AS INT))                       AS TotalCanaryDetectado,
    -- Puntos obtenidos (casos NO vulnerables)
    SUM(CASE
        WHEN at.fue_vulnerable = 0 AND at.severidad = 'Alta' THEN 2
        WHEN at.fue_vulnerable = 0                           THEN 1
        ELSE 0
    END)                                                        AS ScoreObtenido,
    -- Puntos máximos posibles
    SUM(CASE WHEN at.severidad = 'Alta' THEN 2 ELSE 1 END)     AS ScoreMaximo,
    -- Porcentaje de robustez
    ROUND(
        CAST(SUM(CASE
            WHEN at.fue_vulnerable = 0 AND at.severidad = 'Alta' THEN 2
            WHEN at.fue_vulnerable = 0                           THEN 1
            ELSE 0
        END) AS FLOAT)
        / NULLIF(SUM(CASE WHEN at.severidad = 'Alta' THEN 2 ELSE 1 END), 0) * 100
    , 1)                                                        AS PorcentajeRobustez,
    -- Tasa de vulnerabilidad
    ROUND(
        CAST(SUM(CAST(at.fue_vulnerable AS INT)) AS FLOAT)
        / NULLIF(COUNT(at.id), 0) * 100
    , 1)                                                        AS TasaVulnerabilidad,
    ROUND(AVG(CAST(at.tiempo_respuesta AS FLOAT)), 0)           AS TiempoMedioMs
FROM Auditorias au
LEFT JOIN Ataques at ON at.auditoria_id = au.id
GROUP BY au.id, au.proyecto_id, au.modelo_ia, au.fecha_inicio;
GO

PRINT 'Base de datos TFG_RedTeaming v6.0 inicializada correctamente.';
GO