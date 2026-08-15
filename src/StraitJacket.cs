using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Text;
using System.Timers;

namespace StraitJacket
{
    // A Windows Service that blocks websites by managing a dedicated block in
    // the system hosts file, re-enforced on a timer so tampering is reverted.
    //
    // Two sources feed the hosts layer:
    //   * blocklist.txt  - hand-maintained domains (also drive the firewall layer)
    //   * remote feeds    - large auto-updating lists (e.g. adult content),
    //                       refreshed daily and cached to disk.
    // The firewall layer only uses blocklist.txt -- resolving tens of thousands
    // of feed domains to IPs would be impractical and pointless.
    //
    // Enforcement is machine-wide but not unconditional: none of these layers
    // can be scoped to a user, so instead the service stands down entirely while
    // the only people logged on are administrators, and stands back up the
    // moment a standard user appears. SessionGuard owns that decision.
    public class BlockerService : ServiceBase
    {
        public const string SvcName = "StraitJacket";

        const string BeginMarker = "# >>> StraitJacket BEGIN (managed - do not edit) >>>";
        const string EndMarker   = "# <<< StraitJacket END <<<";
        const double FeedRefreshMs = 24 * 60 * 60 * 1000; // daily
        const double FirewallRebuildMinutes = 10;         // cadence for the IP rules

        static readonly string HostsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            @"drivers\etc\hosts");

        readonly string _baseDir;
        readonly string _blocklistPath;
        readonly string _hostsOnlyPath;
        readonly string _appBlockPath;
        readonly string _feedsPath;
        readonly string _feedCachePath;
        readonly string _safeSearchPath;
        readonly string _safeSearchCachePath;
        readonly string _logPath;

        Timer _timer;
        Timer _feedTimer;
        string _lastAppBlockSignature;

        // Domains pulled from remote feeds. Reference is swapped atomically when
        // a refresh completes; read on the enforcement thread.
        HashSet<string> _feedDomains = new HashSet<string>();
        int _feedVersion;

        // Forced SafeSearch: engine hostname -> IP to pin it to. Reference is
        // swapped atomically on refresh.
        Dictionary<string, string> _safeSearchMap = new Dictionary<string, string>();
        int _safeSearchVersion;

        // Local DNS sinkhole. Handles the large feed in memory (instead of a
        // giant hosts file) and forwards everything else upstream.
        DnsSinkhole _sinkhole;
        bool _dnsPinned;
        string _sinkholeSignature;
        readonly object _applyLock = new object();

        // Cache of the generated managed block, rebuilt only when inputs change.
        string _managedBlockCache;
        string _managedSignature;

        // Set while enforcement is stood down for an administrators-only
        // machine. Volatile because an enforcement pass reads it without taking
        // _sessionLock, which exists so a session change never has to wait on a
        // pass that is busy resolving addresses.
        volatile bool _suspended;
        bool _sessionStateKnown;
        readonly object _sessionLock = new object();

        // Serialises firewall passes and records when the rules were last built.
        readonly object _firewallLock = new object();
        DateTime _lastFirewallBuildUtc = DateTime.MinValue;

        public BlockerService()
        {
            ServiceName = SvcName;
            CanStop = true;
            CanShutdown = true;
            CanPauseAndContinue = false;
            // Logon/logoff/switch notifications drive suspend and resume.
            CanHandleSessionChangeEvent = true;

            _baseDir = AppDomain.CurrentDomain.BaseDirectory;
            _blocklistPath = Path.Combine(_baseDir, "blocklist.txt");
            _hostsOnlyPath = Path.Combine(_baseDir, "hostsonly.txt");
            _appBlockPath = Path.Combine(_baseDir, "appblock.txt");
            _feedsPath = Path.Combine(_baseDir, "feeds.txt");
            _feedCachePath = Path.Combine(_baseDir, "feed_cache.txt");
            _safeSearchPath = Path.Combine(_baseDir, "safesearch.txt");
            _safeSearchCachePath = Path.Combine(_baseDir, "safesearch_cache.txt");
            _logPath = Path.Combine(_baseDir, "straitjacket.log");
        }

        static void Main()
        {
            ServiceBase.Run(new BlockerService());
        }

        protected override void OnStart(string[] args)
        {
            Log("Service starting.");

            // Keep OnStart fast: SCM must see the service reach Running quickly.
            // All heavy work (firewall resolution, launching PowerShell to pin
            // DNS, downloading feeds) happens on a background thread.
            _timer = new Timer(30000) { AutoReset = true };
            _timer.Elapsed += (s, e) => { EvaluateSessions(); Apply(); };
            _timer.Start();

            _feedTimer = new Timer(FeedRefreshMs) { AutoReset = true };
            _feedTimer.Elapsed += (s, e) => System.Threading.ThreadPool.QueueUserWorkItem(_ => RefreshRemote());
            _feedTimer.Start();

            System.Threading.ThreadPool.QueueUserWorkItem(_ => Bootstrap());
        }

        void Bootstrap()
        {
            try
            {
                LoadFeedCache();        // make any previously-downloaded feed active immediately
                LoadSafeSearchCache();  // and the last-known SafeSearch mappings

                // Start the sinkhole, then enforce blocking, then pin DNS to it.
                _sinkhole = new DnsSinkhole(Log);
                // The enforcement timer can evaluate sessions before the
                // sinkhole exists, so adopt whatever was decided in the
                // meantime instead of starting out of step with it.
                _sinkhole.Suspended = _suspended;
                bool bound = _sinkhole.Start();

                EvaluateSessions(); // an admin may already be logged on at boot
                Apply();            // hosts block + sinkhole set + firewall rules

                if (bound)
                {
                    PinSystemDns();
                    _dnsPinned = true;
                }
                else
                {
                    Log("DNS sinkhole unavailable; relying on hosts-file blocking only.");
                }

                RefreshRemote(); // download/refresh feeds + SafeSearch
            }
            catch (Exception ex)
            {
                Log("Bootstrap error: " + ex.Message);
            }
        }

        protected override void OnStop()
        {
            Log("Service stop requested.");
            if (_timer != null) _timer.Stop();
            if (_feedTimer != null) _feedTimer.Stop();
            // Restore DNS before tearing down the sinkhole so name resolution
            // keeps working once we stop answering on 127.0.0.1.
            if (_dnsPinned) { UnpinSystemDns(); _dnsPinned = false; }
            if (_sinkhole != null) _sinkhole.Stop();
            // Hosts blocks are intentionally left in place on stop; use uninstall.ps1.
        }

        protected override void OnShutdown()
        {
            if (_timer != null) _timer.Stop();
            if (_feedTimer != null) _feedTimer.Stop();
            // On shutdown leave DNS pinned: the service auto-starts at next boot
            // and the sinkhole comes back up, so blocking is continuous.
            if (_sinkhole != null) _sinkhole.Stop();
        }

        void Apply()
        {
            try
            {
                List<string> manual = ReadDomainFile(_blocklistPath);
                List<string> hostsOnly = ReadDomainFile(_hostsOnlyPath);

                lock (_applyLock)
                {
                    // Keep the sinkhole's data current even while stood down --
                    // it costs nothing, is invisible until the Suspended flag
                    // clears, and means a standard user logging on is blocked
                    // immediately rather than after the next feed refresh.
                    UpdateSinkhole(manual, hostsOnly); // curated lists + large feed

                    if (_suspended) return;

                    EnforceHosts(manual, hostsOnly);   // small curated lists only

                    // Program-scoped firewall block for clients (e.g. Steam)
                    // whose content CDNs the domain/IP layers can't cover.
                    AppBlockManager.Apply(ReadListFile(_appBlockPath), Log, ref _lastAppBlockSignature);
                }

                // Resolving the curated list against public DNS takes over a
                // minute. It runs outside _applyLock deliberately: holding that
                // lock across it would stall the hosts layer behind a pass that
                // is mostly spent waiting on the network.
                if (!_suspended) ApplyFirewall(manual);
            }
            catch (Exception ex)
            {
                Log("Apply error: " + ex.Message);
            }
        }

        // ---- session-driven suspend / resume -----------------------------------

        protected override void OnSessionChange(SessionChangeDescription change)
        {
            // Logon, logoff, and the connect/disconnect pair behind fast user
            // switching all change who is present. Re-reading every session
            // rather than reacting to this one keeps the decision correct when
            // sessions overlap.
            EvaluateSessions();
            Apply();
        }

        void EvaluateSessions()
        {
            bool suspend;
            string summary;
            if (!SessionGuard.TryEvaluate(out suspend, out summary))
            {
                suspend = false; // cannot tell who is here; enforce rather than guess
                summary = "session list unreadable";
            }

            lock (_sessionLock)
            {
                if (_sessionStateKnown && suspend == _suspended) return;
                _sessionStateKnown = true;
                _suspended = suspend;

                // The sinkhole decides every DNS answer, so it is flipped here
                // and NOT behind _applyLock. An enforcement pass can hold that
                // lock while it waits on the network, and queuing behind it
                // would leave a standard user unblocked for the whole pass.
                if (_sinkhole != null) _sinkhole.Suspended = suspend;
            }

            Log(suspend
                ? "Suspended: " + summary + ". Blocking is off until a standard user logs on."
                : "Resumed: " + summary + ". Blocking is on.");

            // Everything below is slower and may queue behind an in-flight pass.
            // Blocking is already correct by this point.
            if (suspend) ReleaseEnforcement();
            else RestoreEnforcement();
        }

        // Stand down the slower layers. The firewall rules are only disabled,
        // not deleted: rebuilding them means re-resolving every blocked domain,
        // which takes over a minute.
        void ReleaseEnforcement()
        {
            // Take _firewallLock so this cannot interleave with a rebuild in
            // flight: FirewallManager.Apply recreates the rules enabled, so a
            // rebuild landing after the disable below would quietly re-block the
            // administrator. Combined with the _suspended re-check inside the
            // pass, that leaves no window.
            lock (_firewallLock)
            {
                lock (_applyLock) RemoveHostsBlock();
                FirewallManager.SetEnabled(false);
                AppBlockManager.SetEnabled(false);
            }
            FlushDns();
        }

        void RestoreEnforcement()
        {
            lock (_applyLock)
            {
                FirewallManager.SetEnabled(true);
                AppBlockManager.SetEnabled(true);
            }
            FlushDns();
            Apply(); // rewrites the hosts block and refreshes the rules
        }

        // Strips the managed block while stood down. The cache is cleared too so
        // the next Apply() writes it back rather than deciding nothing changed.
        void RemoveHostsBlock()
        {
            try
            {
                if (!File.Exists(HostsPath)) return;
                string current = File.ReadAllText(HostsPath);
                if (current.IndexOf(BeginMarker, StringComparison.Ordinal) < 0) return;

                File.WriteAllText(HostsPath, RemoveManagedBlock(current).TrimEnd() + Environment.NewLine);
                _managedSignature = null;
            }
            catch (Exception ex)
            {
                Log("Hosts release error: " + ex.Message);
            }
        }

        // ---- hosts enforcement -------------------------------------------------

        void EnforceHosts(List<string> manual, List<string> hostsOnly)
        {
            string sig = BuildSignature(manual, hostsOnly);
            if (_managedBlockCache == null || sig != _managedSignature)
            {
                _managedBlockCache = BuildManagedBlock(manual, hostsOnly);
                _managedSignature = sig;
            }

            string current = File.Exists(HostsPath) ? File.ReadAllText(HostsPath) : "";
            string body = RemoveManagedBlock(current).TrimEnd();
            string newContent = (body.Length == 0)
                ? _managedBlockCache + Environment.NewLine
                : body + Environment.NewLine + Environment.NewLine + _managedBlockCache + Environment.NewLine;

            if (newContent == current) return;

            File.WriteAllText(HostsPath, newContent);
            FlushDns();
            Log("Hosts file enforced.");
        }

        string BuildSignature(List<string> manual, List<string> hostsOnly)
        {
            // Cheap to compute each pass: local lists are small. The large feed
            // is NOT in the hosts block anymore (it lives in the sinkhole), so
            // only SafeSearch changes need to bump a version here.
            return string.Join(",", manual.ToArray()) + "|" + string.Join(",", hostsOnly.ToArray())
                   + "#ss:" + _safeSearchVersion;
        }

        string BuildManagedBlock(List<string> manual, List<string> hostsOnly)
        {
            var names = new SortedSet<string>(StringComparer.Ordinal);
            foreach (var d in manual)
            {
                names.Add(d);
                if (!d.StartsWith("www.")) names.Add("www." + d);
            }
            foreach (var d in hostsOnly)
            {
                names.Add(d);
                if (!d.StartsWith("www.")) names.Add("www." + d);
            }
            // NOTE: the large remote feed is intentionally NOT written to the
            // hosts file. It is served from memory by the DNS sinkhole, which
            // avoids the Windows DNS Client's large-hosts-file latency.

            var sb = new StringBuilder();
            sb.Append(BeginMarker).Append("\r\n");
            sb.Append("# Managed by StraitJacket - ").Append(names.Count)
              .Append(" host names blocked (feed served via DNS sinkhole). Do not edit.\r\n");
            foreach (var n in names)
                sb.Append("0.0.0.0 ").Append(n).Append("\r\n");

            // Forced SafeSearch redirects. A host that is fully blocked above
            // takes precedence and is skipped here.
            Dictionary<string, string> ss = _safeSearchMap;
            if (ss != null && ss.Count > 0)
            {
                var ssKeys = new List<string>(ss.Keys);
                ssKeys.Sort(StringComparer.Ordinal);
                sb.Append("# SafeSearch redirects\r\n");
                foreach (var host in ssKeys)
                {
                    if (names.Contains(host)) continue;
                    sb.Append(ss[host]).Append(' ').Append(host).Append("\r\n");
                }
            }

            sb.Append(EndMarker);
            return sb.ToString();
        }

        static string RemoveManagedBlock(string content)
        {
            int begin = content.IndexOf(BeginMarker, StringComparison.Ordinal);
            if (begin < 0) return content;

            int end = content.IndexOf(EndMarker, begin, StringComparison.Ordinal);
            string before = content.Substring(0, begin);
            if (end < 0) return before.TrimEnd();

            string after = content.Substring(end + EndMarker.Length);
            return (before.TrimEnd() + after).TrimEnd();
        }

        // ---- firewall enforcement (manual list only) ---------------------------

        // The blocked domains sit on CDNs that hand back a different slice of
        // their address pool on every lookup, so the resolved set never matches
        // the previous one and comparing them rebuilds the rules forever.
        // Accumulating addresses instead does not converge either -- the IPv6
        // pools are large enough to keep growing indefinitely. So the rules are
        // simply rebuilt on a fixed cadence, which bounds both the work and the
        // size of the rule set. Between rebuilds the DNS layers still cover the
        // domains; this layer only exists to catch a custom resolver.
        void ApplyFirewall(List<string> domains)
        {
            // Drop a tick that arrives mid-pass rather than queueing it: a pass
            // can spend over a minute waiting on DNS, and the 30s timer would
            // otherwise stack up passes faster than they drain.
            if (!System.Threading.Monitor.TryEnter(_firewallLock)) return;
            try
            {
                if (_suspended) return;
                if ((DateTime.UtcNow - _lastFirewallBuildUtc).TotalMinutes < FirewallRebuildMinutes) return;

                var ipv4 = new SortedSet<string>();
                var ipv6 = new SortedSet<string>();
                foreach (var d in domains)
                {
                    DnsResolver.Resolve(d, ipv4, ipv6);
                    if (!d.StartsWith("www.")) DnsResolver.Resolve("www." + d, ipv4, ipv6);
                }
                ipv4.Remove("0.0.0.0");
                if (ipv4.Count == 0 && ipv6.Count == 0) return; // resolution failed; keep existing rules

                // A session change can land while the resolution above is still
                // running. Rebuilding now would recreate the rules ENABLED and
                // silently undo the release, so bail out instead.
                if (_suspended) return;

                FirewallManager.Apply(new List<string>(ipv4), new List<string>(ipv6));
                _lastFirewallBuildUtc = DateTime.UtcNow;
                Log("Firewall enforced: " + ipv4.Count + " IPv4 + " + ipv6.Count + " IPv6 addresses blocked.");
            }
            finally { System.Threading.Monitor.Exit(_firewallLock); }
        }

        // ---- DNS sinkhole ------------------------------------------------------

        void UpdateSinkhole(List<string> manual, List<string> hostsOnly)
        {
            if (_sinkhole == null) return;

            string sig = string.Join(",", manual.ToArray()) + "|" + string.Join(",", hostsOnly.ToArray())
                         + "#feed:" + _feedVersion + "#ss:" + _safeSearchVersion;
            if (sig == _sinkholeSignature) return;

            var blocked = new HashSet<string>(StringComparer.Ordinal);
            foreach (var d in manual)
            {
                blocked.Add(d);
                if (!d.StartsWith("www.")) blocked.Add("www." + d);
            }
            foreach (var d in hostsOnly)
            {
                blocked.Add(d);
                if (!d.StartsWith("www.")) blocked.Add("www." + d);
            }
            HashSet<string> feed = _feedDomains;
            if (feed != null)
                foreach (var d in feed) blocked.Add(d);

            _sinkhole.Update(blocked, _safeSearchMap);
            _sinkholeSignature = sig;
            Log("Sinkhole updated: " + blocked.Count + " blocked names in memory.");
        }

        void PinSystemDns()
        {
            RunPowerShell(
                "Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | " +
                "Set-DnsClientServerAddress -ServerAddresses '127.0.0.1','::1' -ErrorAction SilentlyContinue; " +
                "Clear-DnsClientCache");
            Log("System DNS pinned to 127.0.0.1 (sinkhole).");
        }

        void UnpinSystemDns()
        {
            RunPowerShell(
                "Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | " +
                "Set-DnsClientServerAddress -ResetServerAddresses -ErrorAction SilentlyContinue; " +
                "Clear-DnsClientCache");
            Log("System DNS reset to automatic.");
        }

        void RunPowerShell(string command)
        {
            try
            {
                var psi = new ProcessStartInfo("powershell.exe",
                    "-NoProfile -ExecutionPolicy Bypass -Command \"" + command + "\"")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                using (var p = Process.Start(psi))
                {
                    if (!p.WaitForExit(20000)) { try { p.Kill(); } catch { } }
                }
            }
            catch (Exception ex)
            {
                Log("PowerShell run error: " + ex.Message);
            }
        }

        // ---- remote feeds ------------------------------------------------------

        // Refresh everything that requires network access. Runs on a background
        // thread (on start and daily) so OnStart returns promptly.
        void RefreshRemote()
        {
            RefreshFeeds();
            RefreshSafeSearch();
        }

        void RefreshFeeds()
        {
            try
            {
                List<string> urls = ReadFeedUrls();
                if (urls.Count == 0) return;

                HashSet<string> domains = FeedUpdater.Download(urls, Log);
                if (domains.Count == 0)
                {
                    Log("Feed refresh returned no domains; keeping previous set.");
                    return;
                }

                _feedDomains = domains; // atomic reference swap
                _feedVersion++;
                SaveFeedCache(domains);
                Log("Feed updated: " + domains.Count + " domains active.");
                Apply(); // re-enforce immediately with the new feed
            }
            catch (Exception ex)
            {
                Log("Feed refresh error: " + ex.Message);
            }
        }

        List<string> ReadFeedUrls()
        {
            var urls = new List<string>();
            if (!File.Exists(_feedsPath)) return urls;
            foreach (var raw in File.ReadAllLines(_feedsPath))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;
                urls.Add(line);
            }
            return urls;
        }

        void LoadFeedCache()
        {
            try
            {
                if (!File.Exists(_feedCachePath)) return;
                var set = new HashSet<string>();
                foreach (var line in File.ReadAllLines(_feedCachePath))
                {
                    var d = line.Trim();
                    if (d.Length > 0) set.Add(d);
                }
                _feedDomains = set;
                _feedVersion++;
                Log("Loaded feed cache: " + set.Count + " domains.");
            }
            catch (Exception ex)
            {
                Log("Feed cache load error: " + ex.Message);
            }
        }

        void SaveFeedCache(HashSet<string> domains)
        {
            try
            {
                var list = new List<string>(domains);
                File.WriteAllLines(_feedCachePath, list.ToArray());
            }
            catch (Exception ex)
            {
                Log("Feed cache save error: " + ex.Message);
            }
        }

        // ---- forced SafeSearch -------------------------------------------------

        void RefreshSafeSearch()
        {
            try
            {
                List<string[]> rows = SafeSearchManager.ReadConfig(_safeSearchPath);
                if (rows.Count == 0) return;

                Dictionary<string, string> map = SafeSearchManager.Resolve(rows, Log);
                if (map.Count == 0)
                {
                    Log("SafeSearch refresh produced no mappings; keeping previous set.");
                    return;
                }

                _safeSearchMap = map; // atomic reference swap
                _safeSearchVersion++;
                SaveSafeSearchCache(map);
                Log("SafeSearch updated: " + map.Count + " host mappings active.");
                Apply();
            }
            catch (Exception ex)
            {
                Log("SafeSearch refresh error: " + ex.Message);
            }
        }

        void LoadSafeSearchCache()
        {
            try
            {
                if (!File.Exists(_safeSearchCachePath)) return;
                var map = new Dictionary<string, string>();
                foreach (var raw in File.ReadAllLines(_safeSearchCachePath))
                {
                    var parts = raw.Trim().Split(' ');
                    if (parts.Length == 2 && parts[0].Length > 0 && parts[1].Length > 0)
                        map[parts[0]] = parts[1];
                }
                _safeSearchMap = map;
                _safeSearchVersion++;
                Log("Loaded SafeSearch cache: " + map.Count + " mappings.");
            }
            catch (Exception ex)
            {
                Log("SafeSearch cache load error: " + ex.Message);
            }
        }

        void SaveSafeSearchCache(Dictionary<string, string> map)
        {
            try
            {
                var lines = new List<string>();
                foreach (var kv in map) lines.Add(kv.Key + " " + kv.Value);
                File.WriteAllLines(_safeSearchCachePath, lines.ToArray());
            }
            catch (Exception ex)
            {
                Log("SafeSearch cache save error: " + ex.Message);
            }
        }

        // ---- blocklist & misc --------------------------------------------------

        List<string> ReadDomainFile(string path)
        {
            var domains = new List<string>();
            if (!File.Exists(path)) return domains;

            var seen = new HashSet<string>();
            foreach (var raw in File.ReadAllLines(path))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;

                line = line.Replace("https://", "").Replace("http://", "");
                int slash = line.IndexOf('/');
                if (slash >= 0) line = line.Substring(0, slash);
                line = line.Trim().ToLowerInvariant();

                if (line.Length == 0) continue;
                if (seen.Add(line)) domains.Add(line);
            }
            return domains;
        }

        // Plain line reader (preserves case and slashes) for non-domain config
        // such as the app blocklist, which holds executable names and paths.
        List<string> ReadListFile(string path)
        {
            var items = new List<string>();
            if (!File.Exists(path)) return items;
            foreach (var raw in File.ReadAllLines(path))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;
                items.Add(line);
            }
            return items;
        }

        void FlushDns()
        {
            try
            {
                var psi = new ProcessStartInfo("ipconfig", "/flushdns")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                Process.Start(psi);
            }
            catch { /* best effort */ }
        }

        void Log(string msg)
        {
            try
            {
                File.AppendAllText(_logPath,
                    DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + msg + Environment.NewLine);
            }
            catch { /* never let logging break the service */ }
        }
    }
}
