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
}

