// ============================================================
// ComparativaModelosModel.cs — Modelo para la tabla ComparativaModelos
// AI Red Teaming Platform - TFG Ingeniería Informática
// Namespace: TFG_Portal.Models
// ============================================================

namespace TFG_Portal.Models
{
    /// <summary>
    /// Entidad que mapea la tabla dbo.ComparativaModelos.
    /// Almacena métricas agregadas por modelo × tipo de ataque × proyecto.
    /// Se rellena desde el backend Python tras cada auditoría o
    /// manualmente con queries de agregación.
    /// </summary>
    public class ComparativaModelos
    {
        /// <summary>Clave primaria autoincremental.</summary>
        public int Id { get; set; }

        /// <summary>Proyecto al que pertenecen estas métricas.</summary>
        public int ProyectoId { get; set; }

        /// <summary>Nombre del modelo auditado.</summary>
        public string ModeloIa { get; set; } = string.Empty;

        /// <summary>Tipo de ataque (XSS, SQLi, LFI…).</summary>
        public string TipoAtaque { get; set; } = string.Empty;

        // --- Métricas contables ---

        /// <summary>Número total de ataques lanzados contra este modelo para este tipo.</summary>
        public int TotalAtaques { get; set; }

        /// <summary>Número de ataques que resultaron en vulnerabilidad detectada.</summary>
        public int TotalVulnerables { get; set; }

        /// <summary>
        /// Porcentaje de ataques vulnerables (0.00–100.00).
        /// Calculado en BD o en el backend Python.
        /// </summary>
        public decimal TasaVulnerabilidad { get; set; }

        // --- Distribución de severidades ---

        /// <summary>Ataques con severidad Alta.</summary>
        public int SeveridadAlta { get; set; }

        /// <summary>Ataques con severidad Media.</summary>
        public int SeveridadMedia { get; set; }

        /// <summary>Ataques con severidad Baja.</summary>
        public int SeveridadBaja { get; set; }

        // --- Tiempos de respuesta (ms) ---

        /// <summary>Tiempo medio de respuesta del modelo en milisegundos.</summary>
        public int? TiempoMedio { get; set; }

        /// <summary>Tiempo mínimo de respuesta registrado.</summary>
        public int? TiempoMin { get; set; }

        /// <summary>Tiempo máximo de respuesta registrado.</summary>
        public int? TiempoMax { get; set; }

        /// <summary>Fecha y hora en que se calcularon estas métricas.</summary>
        public DateTime FechaCalculo { get; set; }

        // --- Propiedades calculadas para la UI ---

        /// <summary>
        /// Tasa formateada con símbolo % para mostrar directamente en Razor.
        /// </summary>
        public string TasaFormateada => $"{TasaVulnerabilidad:N1} %";

        /// <summary>
        /// Tiempo medio formateado. Muestra "— " si no hay datos.
        /// </summary>
        public string TiempoMedioFormateado =>
            TiempoMedio.HasValue ? $"{TiempoMedio.Value:N0} ms" : "—";

        /// <summary>
        /// Clase CSS para colorear la celda de tasa según el riesgo.
        /// </summary>
        public string TasaCssClass => TasaVulnerabilidad switch
        {
            >= 70 => "text-danger fw-bold",
            >= 40 => "text-warning fw-bold",
            _ => "text-success fw-bold"
        };
    }
}