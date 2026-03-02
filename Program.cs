using System.Security.Principal;
using System.Text;
using System.Text.Json;
using NinjaWatch;

// ---------------------------------------------------------------------------
// 0. Ensure Unicode symbols (↓ ↑ →) render correctly in any console host.
// ---------------------------------------------------------------------------
Console.OutputEncoding = Encoding.UTF8;

// ---------------------------------------------------------------------------
// 1. Elevation check — warn but continue if not running as administrator
// ---------------------------------------------------------------------------
WarnIfNotElevated();

// ---------------------------------------------------------------------------
// 1. Load configuration (appsettings.json → defaults)
// ---------------------------------------------------------------------------
AppConfig config = LoadConfig();

// ---------------------------------------------------------------------------
// 2. Wire up logger and monitor
// ---------------------------------------------------------------------------
var logger  = new ConnectionLogger(config);
var monitor = new ConnectionMonitor(config, logger);

// ---------------------------------------------------------------------------
// 3. Graceful shutdown on CTRL+C / SIGTERM
// ---------------------------------------------------------------------------
using var cts = new CancellationTokenSource();

Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;   // prevent immediate process kill
    Console.WriteLine();
    Console.WriteLine("[NinjaWatch] Shutdown requested — finishing current poll...");
    cts.Cancel();
};

// Also handle SIGTERM (e.g. when stopped as a Windows Service wrapper).
// Guard against ObjectDisposedException: if CTRL+C already ran, the using block
// will have disposed cts before ProcessExit fires during normal shutdown.
AppDomain.CurrentDomain.ProcessExit += (_, _) =>
{
    if (!cts.IsCancellationRequested)
        try { cts.Cancel(); } catch (ObjectDisposedException) { }
};

// ---------------------------------------------------------------------------
// 4. Run
// ---------------------------------------------------------------------------
await monitor.RunAsync(cts.Token);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static void WarnIfNotElevated()
{
    using var identity  = WindowsIdentity.GetCurrent();
    var       principal = new WindowsPrincipal(identity);
    if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("[NinjaWatch] WARNING: Not running as Administrator.");
        Console.WriteLine("             Some connections owned by SYSTEM processes may not be visible.");
        Console.WriteLine("             Re-run from an elevated prompt for full visibility.");
        Console.ResetColor();
        Console.WriteLine();
    }
}

static AppConfig LoadConfig()
{
    const string configFile = "appsettings.json";
    if (File.Exists(configFile))
    {
        try
        {
            string json   = File.ReadAllText(configFile);
            var    config = JsonSerializer.Deserialize<AppConfig>(
                json,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (config is not null)
            {
                Console.WriteLine($"[NinjaWatch] Loaded configuration from {Path.GetFullPath(configFile)}");
                return config;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[NinjaWatch] WARNING: Could not parse {configFile}: {ex.Message} — using defaults.");
        }
    }

    Console.WriteLine("[NinjaWatch] Using default configuration (no appsettings.json found).");
    return new AppConfig();
}
