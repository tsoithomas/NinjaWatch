using System.Net;

namespace NinjaWatch;

/// <summary>
/// TCP connection states from the Windows MIB_TCP_STATE enumeration.
/// </summary>
public enum TcpState
{
    Closed      = 1,
    Listen      = 2,
    SynSent     = 3,
    SynReceived = 4,
    Established = 5,
    FinWait1    = 6,
    FinWait2    = 7,
    CloseWait   = 8,
    Closing     = 9,
    LastAck     = 10,
    TimeWait    = 11,
    DeleteTcb   = 12
}

/// <summary>
/// Represents a single active TCP connection including its owning process.
/// </summary>
public class TcpConnectionInfo
{
    public TcpState   State           { get; set; }
    public IPEndPoint LocalEndpoint   { get; set; } = null!;
    public IPEndPoint RemoteEndpoint  { get; set; } = null!;
    public int        OwningPid       { get; set; }

    /// <summary>
    /// Unique signature used to de-duplicate connections across poll cycles.
    /// Format: PID:LocalEndpoint:RemoteEndpoint
    /// </summary>
    public string Signature =>
        $"{OwningPid}:{LocalEndpoint}:{RemoteEndpoint}";

    // -----------------------------------------------------------------------
    // Raw network-byte-order values from the Windows MIB table.
    // Stored internally so NativeMethods can pass them straight to the
    // EStats API without re-converting through IPEndPoint.
    // -----------------------------------------------------------------------
    internal uint RawState;
    internal uint RawLocalAddr;
    internal uint RawLocalPort;
    internal uint RawRemoteAddr;
    internal uint RawRemotePort;

    // -----------------------------------------------------------------------
    // Byte-transfer data — populated each poll cycle when EnableByteTracking
    // is true and administrator privileges are available.
    // null  = not yet tracked / tracking unavailable for this connection.
    // -----------------------------------------------------------------------

    /// <summary>Bytes received since the previous poll cycle.</summary>
    public ulong? DeltaBytesIn  { get; set; }

    /// <summary>Bytes sent since the previous poll cycle.</summary>
    public ulong? DeltaBytesOut { get; set; }

    /// <summary>Cumulative bytes received since tracking was first enabled for this connection.</summary>
    public ulong? TotalBytesIn  { get; set; }

    /// <summary>Cumulative bytes sent since tracking was first enabled for this connection.</summary>
    public ulong? TotalBytesOut { get; set; }
}

