using System.Text.Json;

namespace NinjaWatch;

/// <summary>
/// Writes connection alerts to a log file (plain text or JSON) and optionally the console.
/// All file writes are protected by a lock so the class is safe to call from multiple threads.
/// </summary>
public sealed class ConnectionLogger
{
    private readonly AppConfig _config;
    private readonly object    _fileLock = new();

    public ConnectionLogger(AppConfig config) => _config = config;

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// <summary>Log a newly detected NinjaOne TCP connection.</summary>
    public void LogConnection(string processName, int pid, TcpConnectionInfo connection)
    {
        if (_config.EnableJsonLogging)
            WriteJson(processName, pid, connection);
        else
            WriteText(processName, pid, connection);

        if (_config.EnableConsoleAlerts)
            PrintConsoleAlert(processName, pid, connection);
    }

    /// <summary>Write an informational message to the log file and stdout.</summary>
    public void LogInfo(string message)
    {
        string line = $"[{Timestamp}] INFO  {message}";
        AppendToFile(line + Environment.NewLine);
        Console.WriteLine(line);
    }

    /// <summary>Write an error message (and optional exception) to the log file and stderr.</summary>
    public void LogError(string message, Exception? ex = null)
    {
        string line = $"[{Timestamp}] ERROR {message}" +
                      (ex is not null ? $" — {ex.GetType().Name}: {ex.Message}" : string.Empty);
        AppendToFile(line + Environment.NewLine);
        Console.Error.WriteLine(line);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private static string Timestamp => DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");

    private void WriteText(string processName, int pid, TcpConnectionInfo conn)
    {
        string entry =
            $"[{Timestamp}] NinjaOne connection detected{Environment.NewLine}" +
            $"  Process : {processName}{Environment.NewLine}" +
            $"  PID     : {pid}{Environment.NewLine}" +
            $"  Local   : {conn.LocalEndpoint}{Environment.NewLine}" +
            $"  Remote  : {conn.RemoteEndpoint}{Environment.NewLine}" +
            $"  State   : {conn.State.ToString().ToUpperInvariant()}{Environment.NewLine}" +
            Environment.NewLine;

        AppendToFile(entry);
    }

    private void WriteJson(string processName, int pid, TcpConnectionInfo conn)
    {
        var record = new
        {
            Timestamp     = DateTime.Now.ToString("o"),
            Event         = "NinjaOneConnectionDetected",
            ProcessName   = processName,
            Pid           = pid,
            LocalAddress  = conn.LocalEndpoint.Address.ToString(),
            LocalPort     = conn.LocalEndpoint.Port,
            RemoteAddress = conn.RemoteEndpoint.Address.ToString(),
            RemotePort    = conn.RemoteEndpoint.Port,
            State         = conn.State.ToString()
        };

        AppendToFile(JsonSerializer.Serialize(record) + Environment.NewLine);
    }

    private static void PrintConsoleAlert(string processName, int pid, TcpConnectionInfo conn)
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine(
            $"[ALERT] {DateTime.Now:HH:mm:ss}  {processName} (PID {pid})  " +
            $"{conn.LocalEndpoint} → {conn.RemoteEndpoint}  [{conn.State.ToString().ToUpperInvariant()}]");
        Console.ResetColor();
    }

    private void AppendToFile(string text)
    {
        lock (_fileLock)
        {
            try
            {
                File.AppendAllText(_config.LogFilePath, text);
            }
            catch (Exception ex)
            {
                // Don't crash the monitor if the log file is temporarily locked.
                Console.Error.WriteLine($"[WARN] Could not write to log file '{_config.LogFilePath}': {ex.Message}");
            }
        }
    }
}

