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
}

