using System;
using System.Collections.Generic;
using System.Net;

namespace StraitJacket
{
    // Downloads one or more remote blocklist feeds (hosts-format or plain
    // domain lists) and parses them into a set of domains. Used for large,
    // auto-updating categories like adult content where a hand-maintained
    // list is impractical.
    static class FeedUpdater
    {
        // Download and merge all feeds. Returns the union of domains found.
        public static HashSet<string> Download(IEnumerable<string> urls, Action<string> log)
        {
            // raw.githubusercontent.com and most CDNs require TLS 1.2+.
            try { ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072; } catch { }

            var domains = new HashSet<string>();
            foreach (var url in urls)
            {
                try
                {
                    string text;
                    using (var wc = new WebClient())
                    {
                        wc.Headers.Add("User-Agent", "StraitJacket/1.0");
                        text = wc.DownloadString(url);
                    }
                    int added = Parse(text, domains);
                    log("Feed downloaded: " + url + " (" + added + " domains)");
                }
                catch (Exception ex)
                {
                    log("Feed download failed: " + url + " -> " + ex.Message);
                }
            }
            return domains;
        }

        // Parse hosts-format ("0.0.0.0 domain") or bare-domain lines into the set.
        static int Parse(string text, HashSet<string> into)
        {
            int added = 0;
            foreach (var rawLine in text.Split('\n'))
            {
                var line = rawLine.Trim();
                if (line.Length == 0) continue;

                int hash = line.IndexOf('#');
                if (hash == 0) continue;
                if (hash > 0) line = line.Substring(0, hash).Trim();
                if (line.Length == 0) continue;

                // Split off a leading IP if present (hosts format).
                string domain;
                int sp = line.IndexOfAny(new[] { ' ', '\t' });
                if (sp > 0)
                {
                    string first = line.Substring(0, sp);
                    if (first == "0.0.0.0" || first == "127.0.0.1" || first == "::1" || first == "::")
                        domain = line.Substring(sp + 1).Trim();
                    else
                        domain = first; // unexpected; take the first token
                }
                else
                {
                    domain = line;
                }

                domain = domain.ToLowerInvariant();
                // Guard against junk: must look like a domain, no spaces.
                if (domain.Length == 0 || domain == "localhost" ||
                    domain.IndexOf('.') < 0 || domain.IndexOf(' ') >= 0)
                    continue;

                if (into.Add(domain)) added++;
            }
            return added;
        }
    }
}
