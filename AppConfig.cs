namespace NinjaWatch;

/// <summary>
/// Application configuration loaded from appsettings.json (or defaults).
/// </summary>
public class AppConfig
{
    /// <summary>How often to poll TCP connections, in seconds.</summary>
    public int PollIntervalSeconds { get; set; } = 60;

    /// <summary>Path to the log file. Relative paths resolve from the working directory.</summary>
    public string LogFilePath { get; set; } = "ninja_log.txt";

    /// <summary>Print a highlighted alert to the console when a new connection is detected.</summary>
    public bool EnableConsoleAlerts { get; set; } = true;

    /// <summary>Write log entries as JSON instead of plain text.</summary>
    public bool EnableJsonLogging { get; set; } = false;

    /// <summary>
    /// Process names to watch (with or without .exe suffix — both are matched).
    /// </summary>
    public string[] TargetProcessNames { get; set; } =
    [
        "NinjaRMMAgent",
        "NinjaRMMAgent.exe"
    ];

    /// <summary>
    /// Track bytes sent and received per connection using GetPerTcpConnectionEStats.
    /// Logs a data-transfer entry each poll cycle when bytes have moved, and a
    /// connection-closed summary when the connection disappears.
    /// Requires administrator privileges; silently disabled if not elevated.
    /// </summary>
    public bool EnableByteTracking { get; set; } = true;

    /// <summary>
    /// Print byte-transfer deltas to the console on each poll cycle.
    /// Only takes effect when both <see cref="EnableByteTracking"/> and
    /// <see cref="EnableConsoleAlerts"/> are also true.
    /// </summary>
    public bool EnableConsoleByteAlerts { get; set; } = false;
}

