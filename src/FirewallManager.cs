using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace StraitJacket
{
    // Manages Windows Firewall block rules (via netsh) for the resolved IPs of
    // the blocked domains. All rules share one name so they are easy to wipe
    // and rebuild as IPs rotate.
    static class FirewallManager
    {
        public const string RuleName = "StraitJacket-Block";
        const int ChunkSize = 200; // keep each rule's remoteip list manageable

        // Replace all StraitJacket rules with a fresh set for the given IPs.
        public static void Apply(List<string> ipv4, List<string> ipv6)
        {
            Clear();
            AddRules(ipv4);
            AddRules(ipv6);
        }

        public static void Clear()
        {
            Netsh("advfirewall firewall delete rule name=\"" + RuleName + "\"");
        }

        static void AddRules(List<string> ips)
        {
            for (int i = 0; i < ips.Count; i += ChunkSize)
            {
                int count = Math.Min(ChunkSize, ips.Count - i);
                string list = string.Join(",", ips.GetRange(i, count).ToArray());
                Netsh("advfirewall firewall add rule name=\"" + RuleName +
                      "\" dir=out action=block remoteip=" + list);
                Netsh("advfirewall firewall add rule name=\"" + RuleName +
                      "\" dir=in action=block remoteip=" + list);
            }
        }

        static void Netsh(string args)
        {
            var psi = new ProcessStartInfo("netsh", args)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            using (var p = Process.Start(psi))
            {
                p.StandardOutput.ReadToEnd();
                p.StandardError.ReadToEnd();
                p.WaitForExit();
            }
        }
    }
}
