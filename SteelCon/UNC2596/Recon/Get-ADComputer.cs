using System;
using System.IO;
using System.Net;
using System.DirectoryServices;
using System.Collections.Generic;

namespace Get_ADComputer
{
    class Program
    {
        static void Main(string[] args)
        {

            DirectorySearcher searcher = new DirectorySearcher();
            searcher.Filter = "(objectclass=computer)";

            List<string> computers = new List<string>();
            List<string> ips = new List<string>();

            try
            {
                foreach (SearchResult computer in searcher.FindAll())
                {
                    computers.Add(computer.GetDirectoryEntry().Properties["cn"][0].ToString());
                }

                foreach (string computer in computers)
                {
                    foreach (var ip in Dns.GetHostAddresses(computer))
                    {
                        if (ip.ToString() != "::1")
                        {
                            Console.WriteLine(ip.ToString());
                            ips.Add(ip.ToString());
                        }
                    }
                }
            }
            catch { }

            File.WriteAllLines($"{Directory.GetCurrentDirectory()}\\ipaddresses.txt", ips.ToArray());

        }
    }
}
