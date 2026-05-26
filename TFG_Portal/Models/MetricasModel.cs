// ============================================================
// MetricasModel.cs — DTOs de métricas y benchmark
// AI Red Teaming Platform - TFG Ingeniería Informática
// v6.0 — benchmark plano
// Contiene: RobustezItem, BenchmarkMetadata, ResultadoBatch,
//           ModeloInfo (complementa AtaqueModel.cs)
// ============================================================

using System.Text.Json.Serialization;

namespace TFG_Portal.Models
{
    // ────────────────────────────────────────────────────────
    // RANKING DE ROBUSTEZ
    // Devuelto por DatabaseService.GetRankingRobustezAsync()
    // ────────────────────────────────────────────────────────

    /// <summary>
    /// Fila del ranking de robustez calculado en BD.
    /// Score: casos no vulnerables × peso (Alta=2, resto=1).
    /// </summary>
    public class RobustezItem
    {
        public string ModeloAuditado { get; set; } = string.Empty;
        public int TotalAtaques { get; set; }
        public int TotalVulnerables { get; set; }
        public double TasaVulnerabilidad { get; set; }
        public int ScoreObtenido { get; set; }
        public int ScoreMaximo { get; set; }
        public int TotalCanary { get; set; }

        /// <summary>Porcentaje de robustez (0–100).</summary>
        public double PorcentajeRobustez =>
            ScoreMaximo == 0 ? 0 :
            Math.Round((double)ScoreObtenido / ScoreMaximo * 100, 1);

        /// <summary>Posición en el ranking (asignada en el controlador).</summary>
        public int Posicion { get; set; }

        // ── Badges para la UI ──────────────────────────────
        public string NivelRobustez => PorcentajeRobustez switch
        {
            >= 90 => "Excelente",
            >= 70 => "Bueno",
            >= 50 => "Moderado",
            _ => "Bajo"
        };

        public string NivelCssClass => PorcentajeRobustez switch
        {
            >= 90 => "badge bg-success",
            >= 70 => "badge bg-info text-dark",
            >= 50 => "badge bg-warning text-dark",
            _ => "badge bg-danger"
        };

        public string TasaFormateada =>
            $"{TasaVulnerabilidad:N1} %";

        public string ScoreFormateado =>
            $"{ScoreObtenido} / {ScoreMaximo}";
    }


    // ────────────────────────────────────────────────────────
    // METADATOS DEL BENCHMARK
    // DTO para GET /benchmark (sin prompts)
    // ────────────────────────────────────────────────────────

    /// <summary>
    /// Metadatos de un caso benchmark devueltos por GET /benchmark.
    /// No incluye system_prompt ni user_prompt por seguridad.
    /// </summary>
    public class BenchmarkMetadata
    {
        [JsonPropertyName("tipo_ataque")]
        public string TipoAtaque { get; set; } = string.Empty;

        [JsonPropertyName("benchmark_id")]
        public string benchmark_id { get; set; } = string.Empty;

        [JsonPropertyName("nombre")]
        public string Nombre { get; set; } = string.Empty;

        [JsonPropertyName("tecnica")]
        public string Tecnica { get; set; } = string.Empty;

        [JsonPropertyName("categoria")]
        public string Categoria { get; set; } = string.Empty;

        [JsonPropertyName("severidad")]
        public string Severidad { get; set; } = string.Empty;

        [JsonPropertyName("owasp_ref")]
        public string OwaspRef { get; set; } = string.Empty;

        [JsonPropertyName("referencia")]
        public string Referencia { get; set; } = string.Empty;

        // ── Propiedades calculadas para la UI ─────────────
        public bool EsAiRedteam => Categoria == "ai_redteam";

        public string SeveridadBadgeClass => Severidad switch
        {
            "Alta" => "badge bg-danger",
            "Media" => "badge bg-warning text-dark",
            _ => "badge bg-info text-dark"
        };

        public string CategoriaBadgeClass =>
            EsAiRedteam ? "badge bg-warning text-dark" : "badge bg-secondary";

        public string CategoriaEtiqueta =>
            EsAiRedteam ? "AI Red Team" : "Clásico";
    }


    // ────────────────────────────────────────────────────────
    // RESULTADO DE AUDITORÍA BATCH
    // DTO para POST /auditar/batch
    // ────────────────────────────────────────────────────────

    /// <summary>
    /// Resultado completo de una auditoría batch devuelto por la API FastAPI.
    /// </summary>
    public class ResultadoBatch
    {
        [JsonPropertyName("auditoria_id")]
        public int AuditoriaId { get; set; }

        [JsonPropertyName("modelo_auditado")]
        public string ModeloAuditado { get; set; } = string.Empty;

        [JsonPropertyName("modelo_juez")]
        public string ModeloJuez { get; set; } = string.Empty;

        [JsonPropertyName("total_ataques")]
        public int TotalAtaques { get; set; }

        [JsonPropertyName("total_vulnerables")]
        public int TotalVulnerables { get; set; }

        [JsonPropertyName("tasa_vulnerabilidad")]
        public double TasaVulnerabilidad { get; set; }

        [JsonPropertyName("tiempo_total_ms")]
        public int TiempoTotalMs { get; set; }

        [JsonPropertyName("resultados")]
        public List<AtaqueResultado> Resultados { get; set; } = new();

        // ── Propiedades calculadas ─────────────────────────
        public string TiempoFormateado =>
            TiempoTotalMs < 60_000
                ? $"{TiempoTotalMs / 1000} s"
                : $"{TiempoTotalMs / 60_000} min {(TiempoTotalMs % 60_000) / 1000} s";

        public string TasaFormateada => $"{TasaVulnerabilidad:N1} %";

        public int TotalCanaryDetectado =>
            Resultados.Count(r => r.CanaryDetectado);

        public int VulnerablesAiRedteam =>
            Resultados.Count(r => r.FueVulnerable && r.Categoria == "ai_redteam");

        public int VulnerablesClasico =>
            Resultados.Count(r => r.FueVulnerable && r.Categoria == "clasico");
    }


    // ────────────────────────────────────────────────────────
    // MODELO INFO
    // DTO para GET /modelos
    // ────────────────────────────────────────────────────────

    /// <summary>
    /// Información de un modelo disponible en Ollama.
    /// </summary>
    public class ModeloInfo
    {
        [JsonPropertyName("nombre")]
        public string Nombre { get; set; } = string.Empty;

        [JsonPropertyName("etiqueta")]
        public string Etiqueta { get; set; } = string.Empty;

        [JsonPropertyName("es_defecto")]
        public bool EsDefecto { get; set; }
    }


    // ────────────────────────────────────────────────────────
    // EXTENSIONES DE AtaqueResultado
    // Campos nuevos v6.0 que complementan AtaqueModel.cs
    // ────────────────────────────────────────────────────────

    // NOTA: Añadir estas propiedades a la clase AtaqueResultado
    // existente en AtaqueModel.cs, ya que C# no permite
    // partial classes entre archivos en la misma clase sin
    // declararla partial. Si AtaqueResultado no es partial,
    // migrar los campos directamente a AtaqueModel.cs:
    //
    //   public string? benchmark_id      { get; set; }
    //   public bool    CanaryDetectado  { get; set; }
    //
    // Y en AtaqueListItem / AtaqueDetalle añadir:
    //   public string? benchmark_id      { get; set; }
    //   public bool    CanaryDetectado  { get; set; }
    //
    // Badges para CanaryDetectado en las vistas:
    //   CanaryDetectado ? "badge bg-danger" : "badge bg-success"


    // ────────────────────────────────────────────────────────
    // INTERFAZ — para inyección de dependencias
    // ────────────────────────────────────────────────────────

    // Añadir a IApiService:
    //   Task<IEnumerable<BenchmarkMetadata>> ObtenerBenchmarkAsync();
    //   Task<ResultadoBatch?> LanzarBatchAsync(int proyectoId,
    //       string? modeloAuditado = null, List<string>? tiposAtaque = null);
    //   Task<IEnumerable<ModeloInfo>> ObtenerModelosAsync();
    //
    // Añadir a IDatabaseService:
    //   Task<BenchmarkAuditoriaResult?> GetBenchmarkResultAsync(int auditoriaId);
    //   Task<IEnumerable<RobustezItem>> GetRankingRobustezAsync(int proyectoId);
}