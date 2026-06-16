using System;
using System.Collections.Generic;
using System.IO;

namespace StraitJacket
{
    // Forced SafeSearch: search providers expose a special hostname whose IP
    // serves a SafeSearch-locked endpoint (with a cert valid for the normal
    // domains). Pointing the normal engine hostnames at that IP in the hosts
    // file forces SafeSearch machine-wide. We resolve the proxy hostname via
    // DnsResolver (bypassing our own hosts entries) to get a current IP.
    static class SafeSearchManager
    {
        // Each row: [proxyHost, engineHost, engineHost, ...]
        public static List<string[]> ReadConfig(string path)
        {
            var rows = new List<string[]>();
            if (!File.Exists(path)) return rows;
            foreach (var raw in File.ReadAllLines(path))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;
                var tokens = line.Split(new[] { ' ', '\t', ',' },
                                        StringSplitOptions.RemoveEmptyEntries);
                if (tokens.Length >= 2) rows.Add(tokens);
            }
            return rows;
        }

        // Returns engineHost (lowercased) -> IP of its SafeSearch proxy.
        public static Dictionary<string, string> Resolve(List<string[]> rows, Action<string> log)
        {
            var map = new Dictionary<string, string>();
            foreach (var row in rows)
            {
                string proxy = row[0];
                var v4 = new List<string>();
                var v6 = new List<string>();
                DnsResolver.Resolve(proxy, v4, v6);

                string ip = v4.Count > 0 ? v4[0] : (v6.Count > 0 ? v6[0] : null);
                if (ip == null)
                {
                    log("SafeSearch: could not resolve " + proxy + "; skipping.");
                    continue;
                }

                for (int i = 1; i < row.Length; i++)
                    map[row[i].ToLowerInvariant()] = ip;

                log("SafeSearch: " + proxy + " -> " + ip + " for " + (row.Length - 1) + " host(s).");
            }
            return map;
        }
    }
}
