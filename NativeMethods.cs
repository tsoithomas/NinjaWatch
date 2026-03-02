using System.Net;
using System.Runtime.InteropServices;

namespace NinjaWatch;

/// <summary>
/// P/Invoke wrapper around the Win32 GetExtendedTcpTable API.
/// Returns all active IPv4 TCP connections together with the PID of the owning process.
/// </summary>
internal static class NativeMethods
{
    // AF_INET = IPv4
    private const int AF_INET = 2;

    // TCP_TABLE_OWNER_PID_ALL — all connections + listeners with owning PID
    private const int TCP_TABLE_OWNER_PID_ALL = 5;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool    bOrder,
        int     ulAf,
        int     TableClass,
        uint    Reserved);

    // -----------------------------------------------------------------------
    // MIB_TCPROW_OWNER_PID — returned by GetExtendedTcpTable
    // -----------------------------------------------------------------------
    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    // -----------------------------------------------------------------------
    // MIB_TCPROW — required by the EStats API (same fields minus OwningPid)
    // -----------------------------------------------------------------------
    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_TCPROW
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
    }

    // -----------------------------------------------------------------------
    // EStats enable/read structures for TcpConnectionEstatsData (type = 1)
    // -----------------------------------------------------------------------
    private const int TcpConnectionEstatsData = 1;

    [StructLayout(LayoutKind.Sequential)]
    private struct TCP_ESTATS_DATA_RW_v0
    {
        public byte EnableCollection;   // BOOLEAN — 1 = enable
    }

    // Explicit layout mirrors the Windows SDK struct exactly on 64-bit.
    [StructLayout(LayoutKind.Explicit, Size = 96)]
    private struct TCP_ESTATS_DATA_ROD_v0
    {
        [FieldOffset( 0)] public ulong DataBytesOut;
        [FieldOffset( 8)] public ulong DataSegsOut;
        [FieldOffset(16)] public ulong DataBytesIn;
        [FieldOffset(24)] public ulong DataSegsIn;
        [FieldOffset(32)] public ulong SegsOut;
        [FieldOffset(40)] public ulong SegsIn;
        [FieldOffset(48)] public uint  SoftErrors;
        [FieldOffset(52)] public uint  SoftErrorReason;
        [FieldOffset(56)] public uint  SndUna;
        [FieldOffset(60)] public uint  SndNxt;
        [FieldOffset(64)] public uint  SndMax;
        // 4 bytes implicit padding → offset 72
        [FieldOffset(72)] public ulong ThruBytesAcked;
        [FieldOffset(80)] public uint  RcvNxt;
        // 4 bytes implicit padding → offset 88
        [FieldOffset(88)] public ulong ThruBytesReceived;
    }

    [DllImport("iphlpapi.dll")]
    private static extern uint SetPerTcpConnectionEStats(
        ref MIB_TCPROW Row,
        int            EstatsType,
        IntPtr         Rw,
        uint           RwVersion,
        uint           RwSize,
        uint           Offset);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetPerTcpConnectionEStats(
        ref MIB_TCPROW Row,
        int            EstatsType,
        IntPtr         Rw,  uint RwVersion,  uint RwSize,
        IntPtr         Ros, uint RosVersion, uint RosSize,
        IntPtr         Rod, uint RodVersion, uint RodSize);

    /// <summary>
    /// Returns all IPv4 TCP connections with their owning PIDs.
    /// Throws <see cref="InvalidOperationException"/> if the native call fails.
    /// </summary>
    public static List<TcpConnectionInfo> GetTcpConnectionsWithPid()
    {
        var connections = new List<TcpConnectionInfo>();
        int bufferSize = 0;

        // First call: retrieve the required buffer size (returns ERROR_INSUFFICIENT_BUFFER).
        GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

        IntPtr tablePtr = Marshal.AllocHGlobal(bufferSize);
        try
        {
            uint result = GetExtendedTcpTable(tablePtr, ref bufferSize, true, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
            if (result != 0)
                throw new InvalidOperationException($"GetExtendedTcpTable failed with error code {result}.");

            int numEntries = Marshal.ReadInt32(tablePtr);
            // Row array starts immediately after the 4-byte entry count.
            IntPtr rowPtr = tablePtr + 4;
            int rowSize  = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);

                // dwLocalAddr / dwRemoteAddr: uint in host-byte-order layout;
                // IPAddress(long) interprets its argument as host byte order → correct on x86/x64.
                var localAddr  = new IPAddress((long)row.dwLocalAddr);
                var remoteAddr = new IPAddress((long)row.dwRemoteAddr);

                // Ports are stored in the low 16 bits in network byte order; swap bytes.
                int localPort  = IPAddress.NetworkToHostOrder((short)(row.dwLocalPort  & 0xFFFF)) & 0xFFFF;
                int remotePort = IPAddress.NetworkToHostOrder((short)(row.dwRemotePort & 0xFFFF)) & 0xFFFF;

                connections.Add(new TcpConnectionInfo
                {
                    State          = (TcpState)row.dwState,
                    LocalEndpoint  = new IPEndPoint(localAddr,  localPort),
                    RemoteEndpoint = new IPEndPoint(remoteAddr, remotePort),
                    OwningPid      = (int)row.dwOwningPid,
                    // Raw values stored for EStats API calls (no conversion needed).
                    RawState       = row.dwState,
                    RawLocalAddr   = row.dwLocalAddr,
                    RawLocalPort   = row.dwLocalPort,
                    RawRemoteAddr  = row.dwRemoteAddr,
                    RawRemotePort  = row.dwRemotePort
                });

                rowPtr += rowSize;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(tablePtr);
        }

        return connections;
    }

    // -----------------------------------------------------------------------
    // EStats helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// Enables per-connection byte tracking for <paramref name="conn"/>.
    /// Must be called once per connection before <see cref="TryGetConnectionBytes"/>.
    /// Requires administrator privileges; returns false on failure.
    /// </summary>
    public static bool TryEnableBytesTracking(TcpConnectionInfo conn)
    {
        var row = ToMibRow(conn);
        var rw  = new TCP_ESTATS_DATA_RW_v0 { EnableCollection = 1 };

        IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf<TCP_ESTATS_DATA_RW_v0>());
        try
        {
            Marshal.StructureToPtr(rw, ptr, false);
            return SetPerTcpConnectionEStats(
                ref row,
                TcpConnectionEstatsData,
                ptr, 0, (uint)Marshal.SizeOf<TCP_ESTATS_DATA_RW_v0>(),
                0) == 0;
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }
    }

    /// <summary>
    /// Reads cumulative bytes in/out for <paramref name="conn"/> since tracking was enabled.
    /// Returns false if the connection has closed or tracking was never enabled.
    /// </summary>
    public static bool TryGetConnectionBytes(TcpConnectionInfo conn,
        out ulong bytesIn, out ulong bytesOut)
    {
        bytesIn = bytesOut = 0;
        var  row     = ToMibRow(conn);
        int  rodSize = Marshal.SizeOf<TCP_ESTATS_DATA_ROD_v0>();
        IntPtr rodPtr = Marshal.AllocHGlobal(rodSize);
        try
        {
            uint result = GetPerTcpConnectionEStats(
                ref row, TcpConnectionEstatsData,
                IntPtr.Zero, 0, 0,
                IntPtr.Zero, 0, 0,
                rodPtr, 0, (uint)rodSize);

            if (result != 0) return false;

            var rod  = Marshal.PtrToStructure<TCP_ESTATS_DATA_ROD_v0>(rodPtr);
            bytesIn  = rod.DataBytesIn;
            bytesOut = rod.DataBytesOut;
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(rodPtr);
        }
    }

    private static MIB_TCPROW ToMibRow(TcpConnectionInfo conn) => new()
    {
        dwState      = conn.RawState,
        dwLocalAddr  = conn.RawLocalAddr,
        dwLocalPort  = conn.RawLocalPort,
        dwRemoteAddr = conn.RawRemoteAddr,
        dwRemotePort = conn.RawRemotePort
    };
}

