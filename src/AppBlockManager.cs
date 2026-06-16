using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace StraitJacket
{
    // Blocks applications from the network with program-scoped Windows Firewall
    // rules (independent of domain/IP). This stops clients like Steam that fetch
    // game content from large, shifting CDN host sets (e.g. *.steamcontent.com,
    // steamcdn-a.akamaihd.net on shared Akamai/Cloudflare IPs) that the
    // exact-match domain and shared-IP firewall layers can't reliably cover.
    //
    // All rules share one name so they are easy to wipe and rebuild.
    static class AppBlockManager
    {
        public const string RuleName = "StraitJacket-AppBlock";

        // Resolve the listed executables to concrete full paths and, if that set
        // changed since the last pass, rebuild the firewall rules. Cheap no-op
        // when nothing changed (called every enforcement tick).
        public static void Apply(List<string> entries, Action<string> log, ref string lastSignature)
        {
            SortedSet<string> paths = ResolvePaths(entries);
            string sig = string.Join("|", new List<string>(paths).ToArray());
            if (sig == lastSignature) return;

            Clear();
            foreach (var p in paths) AddRule(p);
            lastSignature = sig;
            if (paths.Count > 0)
                log("App firewall enforced: " + paths.Count + " executable(s) blocked.");
        }

        public static void Clear()
        {
            Netsh("advfirewall firewall delete rule name=\"" + RuleName + "\"");
        }

        // Each entry is either a full path (contains a separator or drive colon)
        // or a bare executable name. Bare names are matched against currently
        // running processes; Steam is additionally located via the registry so it
        // is blocked even when it isn't running.
        static SortedSet<string> ResolvePaths(List<string> entries)
        {
            var paths = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var raw in entries)
            {
                string entry = raw.Trim();
                if (entry.Length == 0) continue;

                bool looksLikePath = entry.IndexOf('\\') >= 0 || entry.IndexOf('/') >= 0 || entry.IndexOf(':') >= 0;
                if (looksLikePath)
                {
                    try { if (File.Exists(entry)) paths.Add(Path.GetFullPath(entry)); } catch { }
                    continue;
                }

                string procName = entry.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                    ? entry.Substring(0, entry.Length - 4) : entry;
                try
                {
                    foreach (var p in Process.GetProcessesByName(procName))
                    {
                        try
                        {
                            string f = p.MainModule.FileName;
                            if (!string.IsNullOrEmpty(f)) paths.Add(f);
                        }
                        catch { /* access denied / exited between calls */ }
                        finally { p.Dispose(); }
                    }
                }
                catch { }
            }

            AddSteamPaths(entries, paths);
            return paths;
        }

        // If Steam is on the list, resolve its install dir from the registry and
        // pre-block its executables so downloads are stopped even before launch
        // (the running-process scan only catches it once it's already up).
        static void AddSteamPaths(List<string> entries, SortedSet<string> paths)
        {
            bool wantSteam = entries.Exists(delegate(string x)
            {
                return x.Trim().ToLowerInvariant().IndexOf("steam") >= 0;
            });
            if (!wantSteam) return;

            string install = ReadHklm(@"SOFTWARE\WOW6432Node\Valve\Steam", "InstallPath")
                          ?? ReadHklm(@"SOFTWARE\Valve\Steam", "InstallPath")
                          ?? ReadHkcu(@"Software\Valve\Steam", "SteamPath");
            if (string.IsNullOrEmpty(install)) return;

            install = install.Replace('/', '\\');
            AddIfExists(paths, Path.Combine(install, "steam.exe"));
            AddIfExists(paths, Path.Combine(install, "bin\\steamwebhelper.exe"));
            AddIfExists(paths, Path.Combine(install, "bin\\cef\\cef.win7x64\\steamwebhelper.exe"));
            AddIfExists(paths, Path.Combine(install, "steamservice.exe"));
            AddIfExists(paths, Path.Combine(install, "bin\\steamservice.exe"));
        }

        static void AddIfExists(SortedSet<string> paths, string p)
        {
            try { if (File.Exists(p)) paths.Add(p); } catch { }
        }

        static string ReadHklm(string subkey, string value)
        {
            try { using (var k = Registry.LocalMachine.OpenSubKey(subkey)) return k == null ? null : k.GetValue(value) as string; }
            catch { return null; }
        }

        static string ReadHkcu(string subkey, string value)
        {
            try { using (var k = Registry.CurrentUser.OpenSubKey(subkey)) return k == null ? null : k.GetValue(value) as string; }
            catch { return null; }
        }

        static void AddRule(string program)
        {
            Netsh("advfirewall firewall add rule name=\"" + RuleName +
                  "\" dir=out action=block program=\"" + program + "\" enable=yes");
            Netsh("advfirewall firewall add rule name=\"" + RuleName +
                  "\" dir=in action=block program=\"" + program + "\" enable=yes");
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
