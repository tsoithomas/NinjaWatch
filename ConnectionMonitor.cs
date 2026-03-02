using System.Diagnostics;

namespace NinjaWatch;

/// <summary>
/// Core monitoring loop.
/// Periodically enumerates TCP connections, matches them against running NinjaOne
/// processes, and hands newly discovered connections to <see cref="ConnectionLogger"/>.
/// </summary>
public sealed class ConnectionMonitor
{
    private readonly AppConfig         _config;
    private readonly ConnectionLogger  _logger;

    // Normalised target process names (lower-case, no .exe suffix) for fast lookup.
    private readonly HashSet<string> _targetNames;

    // Active connection signatures from the previous poll cycle.
    // Used to suppress duplicate log entries for persistent connections.
    private readonly HashSet<string> _seenSignatures = new();

    public ConnectionMonitor(AppConfig config, ConnectionLogger logger)
    {
        _config = config;
        _logger = logger;

        _targetNames = new HashSet<string>(
            config.TargetProcessNames
                  .Select(n => n.Replace(".exe", string.Empty, StringComparison.OrdinalIgnoreCase)
                                .ToLowerInvariant()),
            StringComparer.Ordinal);
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// <summary>
    /// Starts the monitoring loop. Runs until <paramref name="ct"/> is cancelled.
    /// </summary>
    public async Task RunAsync(CancellationToken ct)
    {
        _logger.LogInfo("NinjaWatch started. Monitoring for NinjaOne agent connections.");
        _logger.LogInfo($"Poll interval : {_config.PollIntervalSeconds}s");
        _logger.LogInfo($"Log file      : {Path.GetFullPath(_config.LogFilePath)}");
        _logger.LogInfo($"Watching      : {string.Join(", ", _config.TargetProcessNames)}");

        while (!ct.IsCancellationRequested)
        {
            try
            {
                Scan();
            }
            catch (Exception ex)
            {
                _logger.LogError("Unexpected error during scan — monitoring will continue", ex);
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(_config.PollIntervalSeconds), ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _logger.LogInfo("NinjaWatch stopped.");
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private void Scan()
    {
        // 1. Find all PIDs belonging to NinjaOne processes.
        Dictionary<int, string> ninjaPids = GetNinjaPids();

        if (ninjaPids.Count == 0)
        {
            // Process not running — clear state so connections are re-logged if it restarts.
            _seenSignatures.Clear();
            return;
        }

        // 2. Enumerate TCP connections.
        List<TcpConnectionInfo> connections;
        try
        {
            connections = NativeMethods.GetTcpConnectionsWithPid();
        }
        catch (Exception ex)
        {
            _logger.LogError("Failed to enumerate TCP connections", ex);
            return;
        }

        // 3. Match connections to NinjaOne PIDs and log new ones.
        var currentSignatures = new HashSet<string>();

        foreach (TcpConnectionInfo conn in connections)
        {
            // Only report connections in the target states.
            if (conn.State is not (TcpState.Established or TcpState.SynSent or TcpState.TimeWait))
                continue;

            if (!ninjaPids.TryGetValue(conn.OwningPid, out string? processName))
                continue;

            string sig = conn.Signature;
            currentSignatures.Add(sig);

            if (_seenSignatures.Add(sig))          // Add returns false if already present.
            {
                _logger.LogConnection(processName, conn.OwningPid, conn);
            }
        }

        // 4. Prune signatures that are no longer active so they can be re-logged if reopened.
        _seenSignatures.IntersectWith(currentSignatures);
    }

    /// <summary>
    /// Returns a mapping of PID → process name for all currently running NinjaOne processes.
    /// </summary>
    private Dictionary<int, string> GetNinjaPids()
    {
        var result = new Dictionary<int, string>();
        try
        {
            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    string normName = process.ProcessName
                        .Replace(".exe", string.Empty, StringComparison.OrdinalIgnoreCase)
                        .ToLowerInvariant();

                    if (_targetNames.Contains(normName))
                        result[process.Id] = process.ProcessName;
                }
                catch
                {
                    // Some processes may deny access to their name — skip silently.
                }
                finally
                {
                    process.Dispose();
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError("Failed to enumerate processes", ex);
        }

        return result;
    }
}

