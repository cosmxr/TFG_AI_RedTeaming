// ============================================================
// AtaqueModel.cs — Modelos relacionados con los ataques
// AI Red Teaming Platform - TFG Ingeniería Informática
// Namespace: TFG_Portal.Models
// ============================================================

namespace TFG_Portal.Models
{
    // --------------------------------------------------------
    // Entidad principal: mapea la tabla dbo.Ataques
    // Campos: id, auditoria_id, tipo_ataque, prompt_enviado,
    //         respuesta_ia, fue_vulnerable, fecha_creacion
    // --------------------------------------------------------

    /// <summary>
    /// Entidad principal de un ataque individual.
    /// Mapeada por Dapper a la tabla dbo.Ataques.
    /// </summary>
    public class Ataque
    {
        /// <summary>Clave primaria autoincremental de la tabla Ataques.</summary>
        public int Id { get; set; }

        /// <summary>
        /// Clave foránea que enlaza con la tabla Auditorias.
        /// Un ataque siempre pertenece a una auditoría padre.
        /// </summary>
        public int AuditoriaId { get; set; }

        /// <summary>
        /// Tipo de ataque ejecutado: XSS, SQLi, LFI, etc.
        /// Corresponde al campo tipo_ataque de la BD.
        /// </summary>
        public string TipoAtaque { get; set; } = string.Empty;

        /// <summary>
        /// Prompt completo enviado al modelo WhiteRabbitNeo.
        /// Puede ser muy extenso (texto libre).
        /// </summary>
        public string PromptEnviado { get; set; } = string.Empty;

        /// <summary>
        /// Respuesta literal generada por la IA.
        /// Corresponde al campo respuesta_ia de la BD.
        /// </summary>
        public string RespuestaIa { get; set; } = string.Empty;

        /// <summary>
        /// Indica si el ataque reveló una vulnerabilidad real.
        /// True = vulnerable (badge rojo en la UI).
        /// Corresponde al campo fue_vulnerable (BIT) de la BD.
        /// </summary>
        public bool FueVulnerable { get; set; }

        /// <summary>
        /// Fecha y hora en que se ejecutó el ataque.
        /// Corresponde al campo fecha_creacion de la BD.
        /// </summary>
        public DateTime FechaCreacion { get; set; }
    }

    // --------------------------------------------------------
    // AtaqueListItem: versión resumida para la vista Historial.
    // El prompt se trunca a 100 chars directamente en SQL
    // para no cargar textos enormes en memoria.
    // --------------------------------------------------------

    /// <summary>
    /// DTO para la lista de ataques en la vista Historial.
    /// El prompt está truncado a 100 caracteres desde la query SQL
    /// con LEFT(prompt_enviado, 100).
    /// </summary>
    public class AtaqueListItem
    {
        /// <summary>Identificador del ataque.</summary>
        public int Id { get; set; }

        /// <summary>Tipo de ataque (XSS, SQLi, LFI…).</summary>
        public string TipoAtaque { get; set; } = string.Empty;

        /// <summary>
        /// Fragmento del prompt (máximo 100 caracteres).
        /// Truncado en SQL con LEFT(prompt_enviado, 100).
        /// </summary>
        public string PromptFragmento { get; set; } = string.Empty;

        /// <summary>Si el ataque resultó en vulnerabilidad encontrada.</summary>
        public bool FueVulnerable { get; set; }

        /// <summary>Fecha de ejecución del ataque.</summary>
        public DateTime FechaCreacion { get; set; }

        /// <summary>
        /// Nombre del modelo IA usado (obtenido del JOIN con Auditorias).
        /// </summary>
        public string ModeloIa { get; set; } = string.Empty;
    }

    // --------------------------------------------------------
    // AtaqueDetalle: versión completa para la vista Detalle.
    // Incluye todos los campos del ataque más los de la
    // auditoría padre (obtenidos mediante JOIN en SQL).
    // --------------------------------------------------------

    /// <summary>
    /// DTO completo para la vista de detalle de un ataque.
    /// Incluye campos de la auditoría padre via JOIN.
    /// </summary>
    public class AtaqueDetalle
    {
        /// <summary>Identificador del ataque.</summary>
        public int Id { get; set; }

        /// <summary>Identificador de la auditoría padre.</summary>
        public int AuditoriaId { get; set; }

        /// <summary>Tipo de ataque ejecutado.</summary>
        public string TipoAtaque { get; set; } = string.Empty;

        /// <summary>Prompt completo enviado a la IA (sin truncar).</summary>
        public string PromptEnviado { get; set; } = string.Empty;

        /// <summary>Respuesta completa de WhiteRabbitNeo.</summary>
        public string RespuestaIa { get; set; } = string.Empty;

        /// <summary>True si se detectó vulnerabilidad.</summary>
        public bool FueVulnerable { get; set; }

        /// <summary>Fecha y hora del ataque.</summary>
        public DateTime FechaCreacion { get; set; }

        // --- Campos de la auditoría padre (JOIN) ---

        /// <summary>
        /// Modelo de IA utilizado en la auditoría padre.
        /// Ejemplo: "WhiteRabbitNeo/WhiteRabbitNeo-2.5-Llama-3.1"
        /// </summary>
        public string ModeloIa { get; set; } = string.Empty;

        /// <summary>Descripción libre de la auditoría padre.</summary>
        public string AuditoriaDescripcion { get; set; } = string.Empty;

        /// <summary>Fecha de creación de la auditoría padre.</summary>
        public DateTime AuditoriaFechaCreacion { get; set; }
    }

    // --------------------------------------------------------
    // AtaquesPorTipo: DTO para el gráfico de barras del Dashboard.
    // Consulta: GROUP BY tipo_ataque con COUNT(*)
    // --------------------------------------------------------

    /// <summary>
    /// DTO para el gráfico "Ataques por tipo" del Dashboard.
    /// Serializado a JSON en DashboardController para Chart.js.
    /// </summary>
    public class AtaquesPorTipo
    {
        /// <summary>
        /// Nombre del tipo de ataque (XSS, SQLi, LFI…).
        /// Etiqueta del eje X en el gráfico de barras.
        /// </summary>
        public string TipoAtaque { get; set; } = string.Empty;

        /// <summary>
        /// Número total de ataques de ese tipo.
        /// Valor del eje Y en el gráfico de barras.
        /// </summary>
        public int Total { get; set; }
    }

    // --------------------------------------------------------
    // AtaquesPorDia: DTO para el gráfico de línea del Dashboard.
    // Consulta: ataques de los últimos 7 días agrupados por fecha.
    // --------------------------------------------------------

    /// <summary>
    /// DTO para el gráfico de línea temporal del Dashboard.
    /// Serializado a JSON en DashboardController para Chart.js.
    /// </summary>
    public class AtaquesPorDia
    {
        /// <summary>
        /// Fecha formateada como "dd/MM" (ej: "07/06").
        /// Etiqueta del eje X en el gráfico de línea.
        /// El formateo se aplica en DatabaseService antes de devolver el DTO.
        /// </summary>
        public string Fecha { get; set; } = string.Empty;

        /// <summary>
        /// Número de ataques ejecutados ese día.
        /// Valor del eje Y en el gráfico de línea temporal.
        /// </summary>
        public int Total { get; set; }
    }
}