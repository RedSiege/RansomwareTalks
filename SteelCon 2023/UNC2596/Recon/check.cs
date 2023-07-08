using System;
using System.IO;
using System.Net;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace PoCs
{
    class Program
    {
        static void Main(string[] args)
        {
            List<IPAddress> ipList = new List<IPAddress>();

            foreach (string ip in File.ReadAllLines(args[0])) { ipList.Add(IPAddress.Parse(ip)); }

            IPAddress[] ipArr = ipList.ToArray();

            foreach (IPAddress cIP in ipArr)
            {
                IntPtr hICMP = IcmpCreateFile();

                ICMP_OPTIONS icmpOpts = new ICMP_OPTIONS();
                icmpOpts.Ttl = 255;

                ICMP_ECHO_REPLY icmpReply = new ICMP_ECHO_REPLY();

                string data = "Date Buffer";

                int retICMP = IcmpSendEcho(hICMP, BitConverter.ToInt32(cIP.GetAddressBytes(), 0), data,
                    (short)data.Length, ref icmpOpts, ref icmpReply, Marshal.SizeOf(icmpReply), 30);

                IcmpCloseHandle(hICMP);

                if (icmpReply.Status == 0) { Console.WriteLine($"{cIP} is up"); }
            }

        }

        [DllImport("icmp.dll", SetLastError = true)]
        static extern IntPtr IcmpCreateFile();

        [DllImport("icmp.dll", SetLastError = true)]
        static extern Int32 IcmpSendEcho(IntPtr icmpHandle, Int32 destinationAddress, string requestData, Int16 requestSize, ref ICMP_OPTIONS requestOptions, ref ICMP_ECHO_REPLY replyBuffer, Int32 replySize, Int32 timeout);

        [DllImport("icmp.dll", SetLastError = true)]
        static extern bool IcmpCloseHandle(IntPtr handle);


        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct ICMP_OPTIONS
        {
            public byte Ttl;
            public byte Tos;
            public byte Flags;
            public byte OptionsSize;
            public IntPtr OptionsData;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        private struct ICMP_ECHO_REPLY
        {
            public int Address;
            public int Status;
            public int RoundTripTime;
            public short DataSize;
            public short Reserved;
            public IntPtr DataPtr;
            public ICMP_OPTIONS Options;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 250)]
            public string Data;
        }
    }
}
