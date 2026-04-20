// ============================================================
// Program.cs — Punto de entrada y configuración de la aplicación
// AI Red Teaming Platform - TFG Ingeniería Informática
// ============================================================

using TFG_Portal.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

builder.Services.AddHttpClient("FastAPI", client =>
{
    var apiUrl = builder.Configuration["ApiSettings:BaseUrl"]
                 ?? "http://localhost:8000";
    client.BaseAddress = new Uri(apiUrl);
    client.Timeout = TimeSpan.FromMinutes(3);
    client.DefaultRequestHeaders.Add("Accept", "application/json");
});

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
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseSession();          // ← una sola vez, ANTES de UseAuthorization
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Dashboard}/{action=Index}/{id?}");

app.Run();