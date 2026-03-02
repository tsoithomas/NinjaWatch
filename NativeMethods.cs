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

    /// <summary>
    /// One row from MIB_TCPTABLE_OWNER_PID.
    /// All fields are in network byte order as returned by Windows.
    /// </summary>
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
                    OwningPid      = (int)row.dwOwningPid
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
}

