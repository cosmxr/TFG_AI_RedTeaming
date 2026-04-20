// ============================================================
// DashboardViewModel.cs — ViewModel tipado para el Dashboard
// AI Red Teaming Platform - TFG Ingeniería Informática
// ============================================================

using TFG_Portal.Models;

namespace TFG_Portal.ViewModels
{
    /// <summary>
    /// ViewModel principal del Dashboard.
    /// Se construye en DashboardController.Index() y se pasa a la vista.
    /// </summary>
    public class DashboardViewModel
    {
        // -------------------------------------------------------
        // SECCIÓN KPIs
        // -------------------------------------------------------

        /// <summary>Total de sesiones de auditoría en la BD.</summary>
        public int TotalAuditorias { get; set; }

        /// <summary>Total de ataques lanzados en todas las auditorías.</summary>
        public int TotalAtaques { get; set; }

        /// <summary>Porcentaje de ataques con vulnerabilidad detectada (0.0 a 100.0).</summary>
        public double PorcentajeVulnerables { get; set; }

        /// <summary>Número de tipos de ataque distintos usados.</summary>
        public int TiposAtaqueDistintos { get; set; }

        // -------------------------------------------------------
        // SECCIÓN GRÁFICOS — Serializados a JSON para Chart.js
        // -------------------------------------------------------

        /// <summary>
        /// JSON array con distribución por tipo.
        /// Formato: [{"TipoAtaque":"XSS","Total":12}, ...]
        /// </summary>
        public string AtaquesPorTipoJson { get; set; } = "[]";

        /// <summary>
        /// JSON array con ataques por día (últimos 7 días).
        /// Formato: [{"Fecha":"07/04","Total":3}, ...]
        /// </summary>
        public string AtaquesPorDiaJson { get; set; } = "[]";

        // -------------------------------------------------------
        // SECCIÓN TABLA
        // -------------------------------------------------------

        /// <summary>Últimas 5 auditorías con estadísticas calculadas.</summary>
        public IEnumerable<AuditoriaResumen> UltimasAuditorias { get; set; }
            = Enumerable.Empty<AuditoriaResumen>();

        // -------------------------------------------------------
        // ESTADO DEL SISTEMA
        // -------------------------------------------------------

        /// <summary>True si la API FastAPI responde en el momento de carga.</summary>
        public bool ApiActiva { get; set; }

        /// <summary>Fecha/hora del servidor al cargar el Dashboard.</summary>
        public DateTime FechaUltimaActualizacion { get; set; } = DateTime.Now;
    }
}
