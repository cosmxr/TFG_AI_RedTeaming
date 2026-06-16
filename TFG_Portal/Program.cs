// ============================================================
// Program.cs — Punto de entrada y configuración
// AI Red Teaming Platform - TFG Ingeniería Informática
// v6.2 — timeouts unificados y cliente duplicado eliminado
// ============================================================

using TFG_Portal.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

// ── HttpClient único para toda la aplicación ──────────────────
// IMPORTANTE: el nombre debe ser exactamente "FastAPI" (mayúsculas)
// porque ApiService lo referencia así.
// MetricasController también usa este mismo cliente registrado.
//
// Regla: HttpClient.Timeout > CancellationTokenSource más largo.
//   TimeoutBatch en ApiService = 35 min  →  ponemos 40 min aquí.
//   Exportar CSV puede tardar varios segundos  →  cubierto por 40 min.
builder.Services.AddHttpClient("FastAPI", client =>
{
    var apiUrl = builder.Configuration["ApiSettings:BaseUrl"]
                 ?? "http://tfg-api:8000";

    client.BaseAddress = new Uri(apiUrl);

    // 40 min > 35 min (TimeoutBatch) > 10 min (TimeoutAtaque)
    // Sin este margen, HttpClient cancela ANTES que el CTS interno
    // y se recibe OperationCanceledException en lugar del timeout real.
    client.Timeout = TimeSpan.FromMinutes(40);

    client.DefaultRequestHeaders.Add("Accept", "application/json");
});

// ELIMINADO: el segundo AddHttpClient("FastApi", ...) con 60 s
// que sobreescribía el de 40 min para el CSV. Un único cliente
// nombrado cubre todos los casos.

builder.Services.AddScoped<IApiService, ApiService>();
builder.Services.AddScoped<IDatabaseService, DatabaseService>();

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromHours(8);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.SetMinimumLevel(
    builder.Environment.IsDevelopment()
        ? LogLevel.Information
        : LogLevel.Warning);

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Dashboard/Error");
    app.UseHsts();
    app.UseHttpsRedirection();
}

app.UseStaticFiles();
app.UseRouting();
app.UseSession();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Dashboard}/{action=Index}/{id?}");

app.Run();