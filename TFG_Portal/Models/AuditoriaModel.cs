// ============================================================
// AuditoriaModel.cs — Modelos relacionados con las auditorías
// AI Red Teaming Platform - TFG Ingeniería Informática
// Namespace: TFG_Portal.Models
// ============================================================

namespace TFG_Portal.Models
{
    // --------------------------------------------------------
    // Entidad principal: mapea la tabla dbo.Auditorias
    // Campos: id, modelo_ia, descripcion, fecha_creacion
    // --------------------------------------------------------

    /// <summary>
    /// Entidad principal que representa una sesión de auditoría.
    /// Mapeada por Dapper a la tabla dbo.Auditorias.
    /// </summary>
    public class Auditoria
    {
        /// <summary>
        /// Clave primaria autoincremental de la tabla Auditorias.
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Identificador del modelo de IA usado en la sesión.
        /// Ejemplo: "WhiteRabbitNeo/WhiteRabbitNeo-2.5-Llama-3.1-8B"
        /// Corresponde al campo modelo_ia de la BD.
        /// </summary>
        public string ModeloIa { get; set; } = string.Empty;

        /// <summary>
        /// Descripción libre de los objetivos de esta sesión
        /// de auditoría. Puede estar vacía.
        /// </summary>
        public string Descripcion { get; set; } = string.Empty;

        /// <summary>
        /// Fecha y hora en que se inició la sesión de auditoría.
        /// Corresponde al campo fecha_creacion de la BD.
        /// </summary>
        public DateTime FechaCreacion { get; set; }
    }

    // --------------------------------------------------------
    // AuditoriaResumen: DTO para la tabla del Dashboard.
    // Incluye la auditoría base más estadísticas calculadas
    // mediante JOINs con la tabla Ataques.
    // --------------------------------------------------------

    /// <summary>
    /// DTO para la tabla de últimas auditorías del Dashboard.
    /// Se obtiene con un JOIN entre Auditorias y Ataques.
    /// </summary>
    public class AuditoriaResumen
    {
        /// <summary>Identificador de la auditoría.</summary>
        public int Id { get; set; }

        /// <summary>Modelo de IA utilizado.</summary>
        public string ModeloIa { get; set; } = string.Empty;

        /// <summary>Descripción de la auditoría.</summary>
        public string Descripcion { get; set; } = string.Empty;

        /// <summary>Fecha de inicio de la auditoría.</summary>
        public DateTime FechaCreacion { get; set; }

        /// <summary>
        /// Número total de ataques ejecutados en esta auditoría.
        /// Calculado con COUNT(*) en el JOIN con Ataques.
        /// </summary>
        public int TotalAtaques { get; set; }

        /// <summary>
        /// Número de ataques que resultaron en vulnerabilidad encontrada.
        /// Calculado con SUM(CASE WHEN fue_vulnerable = 1 THEN 1 ELSE 0 END).
        /// </summary>
        public int AtaquesVulnerables { get; set; }

        /// <summary>
        /// Propiedad calculada (no mapeada a BD): porcentaje de ataques
        /// vulnerables sobre el total. Evita división por cero.
        /// </summary>
        public double PorcentajeVulnerables =>
            TotalAtaques == 0
                ? 0.0
                : Math.Round((double)AtaquesVulnerables / TotalAtaques * 100, 1);

        /// <summary>
        /// Propiedad auxiliar para el badge de estado en la UI.
        /// "Activa" si tiene ataques registrados, "Vacía" si no.
        /// </summary>
        public string EstadoBadge => TotalAtaques > 0 ? "Activa" : "Vacía";
    }
}