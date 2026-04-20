// ============================================================
// AuditoriaController.cs — Controlador de las vistas de auditoría
// AI Red Teaming Platform - TFG Ingeniería Informática
//
// En este Paso 3 solo incluimos el esqueleto con:
//   · Inyección de dependencias
//   · Acciones GET vacías para Nueva, Historial y Detalle
// Los cuerpos completos se desarrollarán en los Pasos 5, 6 y 7.
// ============================================================

using Microsoft.AspNetCore.Mvc;
using TFG_Portal.Services;

namespace TFG_Portal.Controllers
{
    /// <summary>
    /// Controlador que gestiona el flujo completo de auditorías:
    /// lanzar ataques, ver historial y consultar detalles.
    /// </summary>
    public class AuditoriaController : Controller
    {
        // -------------------------------------------------------
        // Dependencias inyectadas
        // -------------------------------------------------------

        /// <summary>Acceso a SQL Server con Dapper.</summary>
        private readonly IDatabaseService _dbService;

        /// <summary>Llamadas a la API FastAPI de Python.</summary>
        private readonly IApiService _apiService;

        /// <summary>Logger del controlador.</summary>
        private readonly ILogger<AuditoriaController> _logger;

        /// <summary>
        /// Constructor con inyección de dependencias.
        /// </summary>
        public AuditoriaController(
            IDatabaseService dbService,
            IApiService apiService,
            ILogger<AuditoriaController> logger)
        {
            _dbService = dbService;
            _apiService = apiService;
            _logger = logger;
        }

        // ============================================================
        // GET /Auditoria/Nueva
        // Formulario para lanzar un nuevo ataque.
        // El cuerpo completo se desarrollará en el Paso 5.
        // ============================================================
        [HttpGet]
        public IActionResult Nueva()
        {
            // TODO (Paso 5): Preparar ViewModel con lista de tipos de ataque
            ViewData["Title"] = "Nueva Auditoría";
            return View();
        }

        // ============================================================
        // GET /Auditoria/Historial
        // Tabla paginada con todos los ataques registrados.
        // El cuerpo completo se desarrollará en el Paso 6.
        // ============================================================
        [HttpGet]
        public IActionResult Historial()
        {
            // TODO (Paso 6): Cargar lista de ataques desde _dbService
            ViewData["Title"] = "Historial de Ataques";
            return View();
        }

        // ============================================================
        // GET /Auditoria/Detalle/{id}
        // Vista de detalle completo de un ataque por ID.
        // El cuerpo completo se desarrollará en el Paso 7.
        // ============================================================
        [HttpGet]
        public IActionResult Detalle(int id)
        {
            // TODO (Paso 7): Cargar detalle del ataque desde _dbService
            ViewData["Title"] = $"Detalle del Ataque #{id}";
            return View();
        }
    }
}