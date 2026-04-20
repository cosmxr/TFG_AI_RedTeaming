// ============================================================
// ProyectoModel.cs — Modelos relacionados con los proyectos
// AI Red Teaming Platform - TFG Ingeniería Informática
// ============================================================

namespace TFG_Portal.Models
{
    /// <summary>
    /// Entidad principal que representa un proyecto de análisis.
    /// Mapeada por Dapper a la tabla dbo.Proyectos.
    /// </summary>
    public class Proyecto
    {
        public int Id { get; set; }
        public string Nombre { get; set; } = string.Empty;
        public string? Descripcion { get; set; }
        public string? ModeloIa { get; set; }
        public DateTime FechaInicio { get; set; }
        public bool Activo { get; set; }

        /// <summary>Número de auditorías del proyecto (calculado con JOIN).</summary>
        public int TotalAuditorias { get; set; }

        /// <summary>Número total de ataques del proyecto (calculado con JOIN).</summary>
        public int TotalAtaques { get; set; }
    }

    /// <summary>
    /// DTO ligero para el selector de proyecto en la navbar/sidebar.
    /// Solo carga los campos necesarios para mostrar la lista.
    /// </summary>
    public class ProyectoResumen
    {
        public int Id { get; set; }
        public string Nombre { get; set; } = string.Empty;
        public DateTime FechaInicio { get; set; }
        public int TotalAuditorias { get; set; }
    }
}