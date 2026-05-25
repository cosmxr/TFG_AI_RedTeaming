-- ============================================================
-- init.sql — TFG AI Red Teaming Platform
-- Inicialización de base de datos SQL Server en Docker
-- Se ejecuta solo si la DB no existe (IF NOT EXISTS en cada objeto)
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
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='Proyectos' AND xtype='U')
CREATE TABLE Proyectos (
    id           INT IDENTITY(1,1) PRIMARY KEY,
    nombre       NVARCHAR(200)     NOT NULL,
    descripcion  NVARCHAR(1000)    NULL,
    modelo_ia    NVARCHAR(200)     NULL,
    fecha_inicio DATETIME          DEFAULT GETDATE(),
    activo       BIT               DEFAULT 1
);
GO

-- ── Tabla: Auditorias ────────────────────────────────────────
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='Auditorias' AND xtype='U')
CREATE TABLE Auditorias (
    id           INT IDENTITY(1,1) PRIMARY KEY,
    proyecto_id  INT               NOT NULL REFERENCES Proyectos(id),
    modelo_ia    NVARCHAR(200)     NOT NULL,
    descripcion  NVARCHAR(500)     NULL,
    estado       NVARCHAR(50)      DEFAULT 'completada',
    fecha_inicio DATETIME          DEFAULT GETDATE()
);
GO

-- ── Tabla: Ataques ───────────────────────────────────────────
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='Ataques' AND xtype='U')
CREATE TABLE Ataques (
    id               INT IDENTITY(1,1) PRIMARY KEY,
    auditoria_id     INT               NOT NULL REFERENCES Auditorias(id),
    tipo_ataque      NVARCHAR(50)      NOT NULL,
    prompt_enviado   NVARCHAR(MAX)     NULL,
    respuesta_ia     NVARCHAR(MAX)     NULL,
    fue_vulnerable   BIT               DEFAULT 0,
    firewall_activo  BIT               DEFAULT 0,
    fecha            DATETIME          DEFAULT GETDATE(),
    severidad        NVARCHAR(20)      NULL,
    tipo_payload     NVARCHAR(20)      NULL,
    justificacion    NVARCHAR(500)     NULL,
    recomendacion    NVARCHAR(500)     NULL,
    tiempo_respuesta INT               NULL,
    iteraciones      INT               DEFAULT 1,
    nivel_prompt     INT               NULL
);
GO

-- ── Tabla: ComparativaModelos ────────────────────────────────
IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='ComparativaModelos' AND xtype='U')
CREATE TABLE ComparativaModelos (
    id                  INT IDENTITY(1,1) PRIMARY KEY,
    proyecto_id         INT               NOT NULL REFERENCES Proyectos(id),
    modelo_ia           NVARCHAR(200)     NOT NULL,
    tipo_ataque         NVARCHAR(50)      NOT NULL,
    total_ataques       INT               DEFAULT 0,
    total_vulnerables   INT               DEFAULT 0,
    tasa_vulnerabilidad FLOAT             DEFAULT 0,
    severidad_alta      INT               DEFAULT 0,
    severidad_media     INT               DEFAULT 0,
    severidad_baja      INT               DEFAULT 0,
    tiempo_medio        FLOAT             NULL,
    tiempo_min          INT               NULL,
    tiempo_max          INT               NULL,
    fecha_calculo       DATETIME          DEFAULT GETDATE()
);
GO

PRINT 'Base de datos TFG_RedTeaming inicializada correctamente.';
GO