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

    // Byte-transfer snapshot per connection signature.
    // Stores the cumulative byte counts from the previous poll so we can
    // compute per-interval deltas.
    private readonly Dictionary<string, ByteSnapshot> _byteSnapshots = new();

    // Immutable snapshot stored between polls.
    private sealed record ByteSnapshot(
        string   ProcessName,
        int      Pid,
        ulong    TotalBytesIn,
        ulong    TotalBytesOut,
        DateTime FirstSeen,
        bool     TrackingEnabled);  // false when SetPerTcpConnectionEStats failed (e.g. not elevated)

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
            // Process not running — flush any open byte snapshots and reset state.
            if (_config.EnableByteTracking)
                LogAndClearAllSnapshots();
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

        // 3. Match connections to NinjaOne PIDs; log new ones and byte deltas.
        var currentSignatures = new HashSet<string>();

        foreach (TcpConnectionInfo conn in connections)
        {
            if (conn.State is not (TcpState.Established or TcpState.SynSent or TcpState.TimeWait))
                continue;

            if (!ninjaPids.TryGetValue(conn.OwningPid, out string? processName))
                continue;

            string sig = conn.Signature;
            currentSignatures.Add(sig);

            if (_seenSignatures.Add(sig))
            {
                // ── New connection ──────────────────────────────────────────
                if (_config.EnableByteTracking)
                {
                    bool enabled = NativeMethods.TryEnableBytesTracking(conn);
                    _byteSnapshots[sig] = new ByteSnapshot(
                        processName, conn.OwningPid, 0, 0, DateTime.Now, enabled);
                }
                _logger.LogConnection(processName, conn.OwningPid, conn);
            }
            else if (_config.EnableByteTracking &&
                     _byteSnapshots.TryGetValue(sig, out ByteSnapshot? snap) &&
                     snap.TrackingEnabled)
            {
                // ── Existing connection — measure bytes moved this interval ─
                if (NativeMethods.TryGetConnectionBytes(conn, out ulong bytesIn, out ulong bytesOut))
                {
                    // Guard against counter resets (connection briefly disappeared).
                    ulong deltaIn  = bytesIn  >= snap.TotalBytesIn  ? bytesIn  - snap.TotalBytesIn  : bytesIn;
                    ulong deltaOut = bytesOut >= snap.TotalBytesOut ? bytesOut - snap.TotalBytesOut : bytesOut;

                    conn.DeltaBytesIn  = deltaIn;
                    conn.DeltaBytesOut = deltaOut;
                    conn.TotalBytesIn  = bytesIn;
                    conn.TotalBytesOut = bytesOut;

                    if (deltaIn > 0 || deltaOut > 0)
                        _logger.LogByteTransfer(processName, conn.OwningPid, conn);

                    _byteSnapshots[sig] = snap with
                    {
                        TotalBytesIn  = bytesIn,
                        TotalBytesOut = bytesOut
                    };
                }
            }
        }

        // 4. Log connections that disappeared since the last poll.
        if (_config.EnableByteTracking)
        {
            foreach (string closed in _seenSignatures.Where(s => !currentSignatures.Contains(s)))
            {
                if (_byteSnapshots.Remove(closed, out ByteSnapshot? snap))
                    _logger.LogConnectionClosed(
                        snap.ProcessName, snap.Pid, closed,
                        snap.TotalBytesIn, snap.TotalBytesOut, snap.FirstSeen);
            }
        }

        // 5. Prune seen set so closed connections can be re-logged if they reopen.
        _seenSignatures.IntersectWith(currentSignatures);
    }

    /// <summary>
    /// Logs a closed-connection summary for every tracked connection and clears state.
    /// Called when the NinjaOne process disappears entirely between polls.
    /// </summary>
    private void LogAndClearAllSnapshots()
    {
        foreach (var (sig, snap) in _byteSnapshots)
            _logger.LogConnectionClosed(
                snap.ProcessName, snap.Pid, sig,
                snap.TotalBytesIn, snap.TotalBytesOut, snap.FirstSeen);
        _byteSnapshots.Clear();
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

