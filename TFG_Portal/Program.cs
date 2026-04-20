// ============================================================
// Program.cs — Punto de entrada y configuración de la aplicación
// AI Red Teaming Platform - TFG Ingeniería Informática
// ============================================================

using TFG_Portal.Services;

var builder = WebApplication.CreateBuilder(args);

// -------------------------------------------------------
// 1. SERVICIOS MVC
//    Registramos controladores con vistas Razor
// -------------------------------------------------------
builder.Services.AddControllersWithViews();

// -------------------------------------------------------
// 2. HTTP CLIENT FACTORY (patrón recomendado por Microsoft)
//    Se usa para llamar a la API FastAPI de Python.
//    La URL base se lee desde appsettings.json para facilitar
//    el cambio de entorno (dev → producción).
// -------------------------------------------------------
builder.Services.AddHttpClient("FastAPI", client =>
{
    // Leer URL de la API desde la configuración
    var apiUrl = builder.Configuration["ApiSettings:BaseUrl"]
                 ?? "http://localhost:8000";
    client.BaseAddress = new Uri(apiUrl);
    client.Timeout = TimeSpan.FromSeconds(60); // Timeout generoso: la IA puede tardar
    client.DefaultRequestHeaders.Add("Accept", "application/json");
});

// -------------------------------------------------------
// 3. SERVICIOS PROPIOS (escritos en VB.NET)
//    - ApiService:      Llama a los endpoints de FastAPI
//    - DatabaseService: Consulta SQL Server con Dapper
//    Se registran como Scoped (una instancia por petición HTTP)
// -------------------------------------------------------
builder.Services.AddScoped<IApiService, ApiService>();
builder.Services.AddScoped<IDatabaseService, DatabaseService>();

// -------------------------------------------------------
// 4. SESIÓN (para mensajes flash entre redirecciones)
// -------------------------------------------------------
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// -------------------------------------------------------
// 5. LOGGING: nivel Info en desarrollo, Warning en producción
// -------------------------------------------------------
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.SetMinimumLevel(
    builder.Environment.IsDevelopment()
        ? LogLevel.Information
        : LogLevel.Warning);

// ============================================================
// CONSTRUCCIÓN DEL PIPELINE HTTP
// ============================================================
var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    // Página de error personalizada (no stack trace al usuario)
    app.UseExceptionHandler("/Dashboard/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();

// Servir archivos estáticos (CSS, JS, imágenes) desde wwwroot/
app.UseStaticFiles();

app.UseRouting();
app.UseSession();
app.UseAuthorization();

// -------------------------------------------------------
// RUTAS MVC
//    Ruta por defecto → Dashboard/Index
// -------------------------------------------------------
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Dashboard}/{action=Index}/{id?}");

app.Run();