using System.Text.Json.Serialization;
// ============================================================
// AtaqueModel.cs — Modelos relacionados con los ataques
// AI Red Teaming Platform - TFG Ingeniería Informática
// Namespace: TFG_Portal.Models
// ============================================================

namespace TFG_Portal.Models
{
    // --------------------------------------------------------
    // Categorías de ataque (debe coincidir con 02_api.py)
    // --------------------------------------------------------
    public static class CategoriasAtaque
    {
        public static readonly List<string> Clasico = new()
            { "XSS", "SQLI", "LFI", "CSRF" };

        public static readonly List<string> AiRedteam = new()
            { "PROMPT_INJECTION", "JAILBREAK", "SYSTEM_PROMPT_LEAKAGE",
              "DATA_EXTRACTION", "CONTEXT_MANIPULATION", "INDIRECT_INJECTION" };

        public static string ObtenerCategoria(string tipoAtaque) =>
            AiRedteam.Contains(tipoAtaque?.ToUpper() ?? "") ? "ai_redteam" : "clasico";

        public static string EtiquetaAmigable(string tipoAtaque) => tipoAtaque?.ToUpper() switch
        {
            "XSS"                   => "XSS",
            "SQLI"                  => "SQL Injection",
            "LFI"                   => "LFI",
            "CSRF"                  => "CSRF",
            "PROMPT_INJECTION"      => "Prompt Injection",
            "JAILBREAK"             => "Jailbreak",
            "SYSTEM_PROMPT_LEAKAGE" => "System Prompt Leakage",
            "DATA_EXTRACTION"       => "Data Extraction",
            "CONTEXT_MANIPULATION"  => "Context Manipulation",
            "INDIRECT_INJECTION"    => "Indirect Injection",
            _                       => tipoAtaque ?? "—"
        };

        public static string DescripcionAtaque(string tipoAtaque) => tipoAtaque?.ToUpper() switch
        {
            "XSS"                   => "Intenta que el modelo genere payloads XSS funcionales.",
            "SQLI"                  => "Intenta que el modelo genere inyecciones SQL funcionales.",
            "LFI"                   => "Intenta que el modelo genere rutas de traversal funcionales.",
            "CSRF"                  => "Intenta que el modelo genere formularios CSRF funcionales.",
            "PROMPT_INJECTION"      => "Inyecta instrucciones en datos procesados para alterar el comportamiento.",
            "JAILBREAK"             => "Intenta que el modelo adopte un rol sin restricciones (DAN, HackerAI…).",
            "SYSTEM_PROMPT_LEAKAGE" => "Intenta extraer las instrucciones de sistema privadas del modelo.",
            "DATA_EXTRACTION"       => "Intenta que el modelo revele datos de su contexto o entrenamiento.",
            "CONTEXT_MANIPULATION"  => "Usa autorizaciones falsas para modificar el comportamiento del modelo.",
            "INDIRECT_INJECTION"    => "Embebe instrucciones maliciosas en datos que el modelo procesa.",
            _                       => ""
        };
    }

    // --------------------------------------------------------
    // TiposAtaqueResponse: DTO de respuesta del endpoint
    // GET /tipos_ataque de la API FastAPI
    // --------------------------------------------------------
    public class TiposAtaqueResponse
    {
        [JsonPropertyName("clasico")]
        public List<string> Clasico { get; set; } = new();

        [JsonPropertyName("ai_redteam")]   // ← ESTE ES EL FIX
        public List<string> AiRedteam { get; set; } = new();

        [JsonPropertyName("todos")]
        public List<string> Todos { get; set; } = new();
    }

    // --------------------------------------------------------
    // AtaqueResultado: DTO de respuesta del endpoint
    // POST /atacar — mapeado desde el JSON de FastAPI
    // --------------------------------------------------------
    public class AtaqueResultado
    {
        public int     AuditoriaId     { get; set; }
        public int?    AtaqueId        { get; set; }   
        public string  TipoAtaque      { get; set; } = string.Empty;
        public string  PromptEnviado   { get; set; } = string.Empty;
        public string  RespuestaIa     { get; set; } = string.Empty;
        public bool    FueVulnerable   { get; set; }
        public string? Severidad       { get; set; }
        public string? TipoPayload     { get; set; }
        public string? Justificacion   { get; set; }
        public string? Recomendacion   { get; set; }
        public int?    TiempoRespuesta { get; set; }
        public int     Iteraciones     { get; set; } = 1;
        public int?    NivelPrompt     { get; set; }
        public string? ModeloAuditado  { get; set; }

        // Calculada en cliente para no depender del backend
        public string Categoria =>
            CategoriasAtaque.ObtenerCategoria(TipoAtaque);

        // Usada en la redirección tras POST /atacar
        public int Id => AuditoriaId;
    }

    // --------------------------------------------------------
    // Entidad principal: mapea la tabla dbo.Ataques
    // --------------------------------------------------------
    public class Ataque
    {
        public int      Id             { get; set; }
        public int      AuditoriaId    { get; set; }
        public string   TipoAtaque     { get; set; } = string.Empty;
        public string   PromptEnviado  { get; set; } = string.Empty;
        public string   RespuestaIa    { get; set; } = string.Empty;
        public bool     FueVulnerable  { get; set; }
        public bool     FirewallActivo { get; set; }
        public DateTime FechaCreacion  { get; set; }
        public string?  Severidad      { get; set; }
        public string?  TipoPayload    { get; set; }
        public string?  Justificacion  { get; set; }
        public string?  Recomendacion  { get; set; }
        public int?     TiempoRespuesta { get; set; }
        public int      Iteraciones    { get; set; } = 1;
        public int?     NivelPrompt    { get; set; }

        public string Categoria =>
            CategoriasAtaque.ObtenerCategoria(TipoAtaque);
    }

    // --------------------------------------------------------
    // AtaqueListItem: versión resumida para la vista Historial
    // --------------------------------------------------------
    public class AtaqueListItem
    {
        public int      Id               { get; set; }
        public string   TipoAtaque       { get; set; } = string.Empty;
        public string   PromptFragmento  { get; set; } = string.Empty;
        public bool     FueVulnerable    { get; set; }
        public DateTime FechaCreacion    { get; set; }
        public string   ModeloIa         { get; set; } = string.Empty;
        public string?  Severidad        { get; set; }
        public string?  TipoPayload      { get; set; }
        public int?     NivelPrompt      { get; set; }

        // ── Categoría ──────────────────────────────────────────
        public string Categoria =>
            CategoriasAtaque.ObtenerCategoria(TipoAtaque);

        public bool EsAiRedteam =>
            Categoria == "ai_redteam";

        // ── Badges Bootstrap ───────────────────────────────────
        public string SeveridadBadgeClass => Severidad switch
        {
            "Alta"  => "badge bg-danger",
            "Media" => "badge bg-warning text-dark",
            "Baja"  => "badge bg-info text-dark",
            _       => "badge bg-secondary"
        };

        public string TipoPayloadBadgeClass => TipoPayload switch
        {
            "funcional" => "badge bg-primary",
            "generico"  => "badge bg-secondary",
            "rechazo"   => "badge bg-success",
            _           => "badge bg-light text-dark"
        };

        // ── Nivel de prompt ────────────────────────────────────
        public string NivelPromptEtiqueta => NivelPrompt switch
        {
            1 => "Directo",
            2 => "Investigador",
            3 => "CTF/Educativo",
            _ => "—"
        };

        public string NivelPromptBadgeClass => NivelPrompt switch
        {
            1 => "badge-nivel badge-nivel-1",
            2 => "badge-nivel badge-nivel-2",
            3 => "badge-nivel badge-nivel-3",
            _ => "badge-nivel"
        };

        // ── Categoría badge ────────────────────────────────────
        public string CategoriaBadgeClass =>
            EsAiRedteam
                ? "badge bg-warning text-dark"
                : "badge bg-secondary";

        public string CategoriaEtiqueta =>
            EsAiRedteam ? "AI" : "Web";
    }

    // --------------------------------------------------------
    // AtaqueDetalle: versión completa para la vista Detalle
    // --------------------------------------------------------
    public class AtaqueDetalle
    {
        public int      Id                    { get; set; }
        public int      AuditoriaId           { get; set; }
        public string   TipoAtaque            { get; set; } = string.Empty;
        public string   PromptEnviado         { get; set; } = string.Empty;
        public string   RespuestaIa           { get; set; } = string.Empty;
        public bool     FueVulnerable         { get; set; }
        public bool     FirewallActivo        { get; set; }
        public DateTime FechaCreacion         { get; set; }
        public string   ModeloIa              { get; set; } = string.Empty;
        public string   AuditoriaDescripcion  { get; set; } = string.Empty;
        public DateTime AuditoriaFechaCreacion { get; set; }
        public string?  Severidad             { get; set; }
        public string?  TipoPayload           { get; set; }
        public string?  Justificacion         { get; set; }
        public string?  Recomendacion         { get; set; }
        public int?     TiempoRespuesta       { get; set; }
        public int      Iteraciones           { get; set; } = 1;
        public int?     NivelPrompt           { get; set; }

        // ── Categoría ──────────────────────────────────────────
        public string Categoria =>
            CategoriasAtaque.ObtenerCategoria(TipoAtaque);

        public bool EsAiRedteam =>
            Categoria == "ai_redteam";

        public string EtiquetaAmigable =>
            CategoriasAtaque.EtiquetaAmigable(TipoAtaque);

        public string Descripcion =>
            CategoriasAtaque.DescripcionAtaque(TipoAtaque);

        // ── Propiedades formateadas para UI ───────────────────
        public string TiempoRespuestaFormateado =>
            TiempoRespuesta.HasValue
                ? $"{TiempoRespuesta.Value:N0} ms"
                : "—";

        public string SeveridadBadgeClass => Severidad switch
        {
            "Alta"  => "badge bg-danger",
            "Media" => "badge bg-warning text-dark",
            "Baja"  => "badge bg-info text-dark",
            _       => "badge bg-secondary"
        };

        public string NivelPromptEtiqueta => NivelPrompt switch
        {
            1 => "Directo",
            2 => "Investigador",
            3 => "CTF/Educativo",
            _ => "—"
        };

        public string NivelPromptBadgeClass => NivelPrompt switch
        {
            1 => "badge-nivel badge-nivel-1",
            2 => "badge-nivel badge-nivel-2",
            3 => "badge-nivel badge-nivel-3",
            _ => "badge-nivel"
        };
    }

    // --------------------------------------------------------
    // DTOs para gráficos del Dashboard (sin cambios)
    // --------------------------------------------------------

    public class AtaquesPorTipo
    {
        public string TipoAtaque { get; set; } = string.Empty;
        public int    Total       { get; set; }
        public string Categoria  => CategoriasAtaque.ObtenerCategoria(TipoAtaque);
    }

    public class AtaquesPorDia
    {
        public string Fecha { get; set; } = string.Empty;
        public int    Total  { get; set; }
    }

    public class AtaqueSeveridadResumen
    {
        public string Severidad { get; set; } = string.Empty;
        public int    Total      { get; set; }

        public string Color => Severidad switch
        {
            "Alta"  => "#dc3545",
            "Media" => "#fd7e14",
            "Baja"  => "#0dcaf0",
            _       => "#6c757d"
        };
    }

    public class ResumenAuditoria
    {
        public int      AuditoriaId            { get; set; }
        public string   ModeloIa               { get; set; } = string.Empty;
        public int      TotalAtaques           { get; set; }
        public int      TotalVulnerables       { get; set; }
        public string?  SeveridadMasFrecuente  { get; set; }
        public string?  TipoPayloadMasFrecuente { get; set; }
        public int?     TiempoMedioRespuesta   { get; set; }
        public DateTime FechaInicio            { get; set; }
        public DateTime FechaUltimoAtaque      { get; set; }
        public int?     NivelPrompt            { get; set; }

        public double TasaVulnerabilidad =>
            TotalAtaques > 0
                ? Math.Round((double)TotalVulnerables / TotalAtaques * 100, 1)
                : 0;

        public string TiempoMedioFormateado =>
            TiempoMedioRespuesta.HasValue
                ? $"{TiempoMedioRespuesta.Value:N0} ms"
                : "Sin datos";

        public string TasaFormateada => $"{TasaVulnerabilidad:N1} %";

        public string NivelPromptDescripcion => NivelPrompt switch
        {
            1 => "Directo",
            2 => "Investigador",
            3 => "CTF / Educativo",
            _ => "—"
        };
    }
}