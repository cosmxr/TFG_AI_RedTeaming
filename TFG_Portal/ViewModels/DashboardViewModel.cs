// ============================================================
// DashboardViewModel.cs — ViewModel tipado para el Dashboard
// AI Red Teaming Platform - TFG Ingeniería Informática
// ============================================================

using TFG_Portal.Models;

namespace TFG_Portal.ViewModels
{
    public class DashboardViewModel
    {
        // ── KPIs ────────────────────────────────────────────────
        public int TotalAuditorias { get; set; }
        public int TotalAtaques { get; set; }
        public double PorcentajeVulnerables { get; set; }
        public int TiposAtaqueDistintos { get; set; }
        public int TotalCanaryDetectado { get; set; }

        public ProyectoResumen? ProyectoActivo { get; set; }
        public IEnumerable<ProyectoResumen> TodosProyectos { get; set; }
            = Enumerable.Empty<ProyectoResumen>();

        // ── Gráficos (JSON para Chart.js) ───────────────────────
        public string AtaquesPorTipoJson { get; set; } = "[]";
        public string AtaquesPorDiaJson { get; set; } = "[]";
        public string AtaquesPorSeveridadJson { get; set; } = "[]";

        // ── Tabla ───────────────────────────────────────────────
        public IEnumerable<AuditoriaResumen> UltimasAuditorias { get; set; }
            = Enumerable.Empty<AuditoriaResumen>();

        // ── Estado ──────────────────────────────────────────────
        public bool ApiActiva { get; set; }
        public DateTime FechaUltimaActualizacion { get; set; } = DateTime.Now;
    }
}