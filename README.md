# StraitJacket

A Windows service that blocks access to websites for **every** user on the
machine. It starts automatically at boot, restarts itself if it fails, and
cannot be stopped by non-administrator users.

## How it works

The service maintains a managed block in the system hosts file
(`C:\Windows\System32\drivers\etc\hosts`), re-applied **every 30 seconds** so
any tampering is automatically reverted. It draws blocked domains from several
sources and adds a complementary firewall layer:

### Hosts-file layer (re-enforced every 30s)

Four sources are merged into the managed block:

| Source file | Scope | Firewall too? |
|-------------|-------|---------------|
| `blocklist.txt`  | Hand-curated domains (social media, news, adult, AI-NSFW, …). A `www.` variant is added automatically. | ✅ Yes |
| `hostsonly.txt`  | Domains blocked at the **hosts layer only** — used for sites on shared infrastructure (e.g. Google search shares front-end IPs with Gmail/Drive) where IP blocking would cause collateral damage. Also where **search-engine blocking** lives. | ❌ No |
| `feeds.txt`      | URLs of large auto-updating blocklists (default: StevenBlack porn-only, ~77k domains). Downloaded on start + **daily**, cached to disk so blocking is active immediately at boot and survives offline boots / failed downloads. | ❌ No |
| `safesearch.txt` | Forced-SafeSearch redirects: pins search engines to their providers' SafeSearch IPs. (Disabled by default — engines are fully blocked instead; see below.) | ❌ No |

### Firewall layer (curated list only)

For the `blocklist.txt` domains, the service resolves the real IPs by querying
public DNS resolvers directly (1.1.1.1 / 8.8.8.8), **bypassing** the hosts file,
then blocks those IPv4/IPv6 addresses with inbound + outbound firewall rules
named `StraitJacket-Block`. This catches users who switch to a custom DNS server
to evade the hosts file. Rules are rebuilt only when the resolved IP set changes.
The feed/hosts-only lists are deliberately **not** sent to the firewall (too many
domains, and shared-IP collateral risk).

### Search-engine policy

`hostsonly.txt` blocks **all mainstream search engines** (Google + country TLDs,
Bing, Yahoo, DuckDuckGo, Yandex, Baidu, Brave, Startpage, Ecosia, Qwant,
Perplexity, common SearXNG instances, …) **except `lite.duckduckgo.com`**, which
is left reachable as the one allowed, text-only (image-free) search engine.
Because the hosts file is exact-match, blocking `duckduckgo.com` does not affect
the `lite.` subdomain, and blocking `google.com` does not affect Gmail/Drive.

> Set `https://lite.duckduckgo.com/lite/?q=%s` as your browser's default search
> engine, otherwise the address bar will try the (now-blocked) default and fail.

### Hardening

The service runs as **LocalSystem**, installs under **Program Files** (not
writable by standard users), and is configured with a security descriptor that
lets only SYSTEM and Administrators start/stop/reconfigure it. Failure-recovery
actions restart it automatically.

## Requirements

- Windows with .NET Framework 4.x (the in-box `csc.exe` is used to compile —
  **no .NET SDK needed**).
- An elevated (Administrator) PowerShell to install/uninstall.

## Install

```powershell
# from an elevated PowerShell, in this folder:
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

## Configure

All config files live in `C:\Program Files\StraitJacket\` after install. Edit
them as admin (standard users can't write there), one entry per line:

- `blocklist.txt`  — domains to block at both layers
- `hostsonly.txt`  — domains to block at the hosts layer only (search engines, etc.)
- `feeds.txt`      — auto-updating blocklist feed URLs
- `safesearch.txt` — forced-SafeSearch redirects (optional)

Changes are picked up within ~30 seconds, or apply immediately with:

```powershell
sc.exe stop StraitJacket ; sc.exe start StraitJacket
```

## Uninstall

```powershell
# from an elevated PowerShell, in this folder:
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
```

Removes the service, strips the managed block from the hosts file, deletes the
firewall rules, and removes the install directory.

## Files

| File                     | Purpose                                                  |
|--------------------------|----------------------------------------------------------|
| `src/StraitJacket.cs`    | The Windows Service: enforcement loop, hosts management.  |
| `src/DnsResolver.cs`     | Direct-to-DNS resolver (bypasses the hosts file).         |
| `src/FirewallManager.cs` | Builds/clears the Windows Firewall block rules.           |
| `src/FeedUpdater.cs`     | Downloads & parses remote blocklist feeds.                |
| `src/SafeSearchManager.cs` | Resolves and maps forced-SafeSearch endpoints.          |
| `blocklist.txt`          | Curated domains (both layers).                            |
| `hostsonly.txt`          | Hosts-only blocks, incl. search engines.                  |
| `feeds.txt`              | Auto-updating feed URLs.                                  |
| `safesearch.txt`         | Forced-SafeSearch redirects.                              |
| `install.ps1`            | Compile, install, harden, and start the service.          |
| `uninstall.ps1`          | Stop/remove the service and clean up.                     |

## Notes & limitations

- **VPN / proxy** traffic is not blocked — it exits via a different IP the
  service never sees. For fully tamper-proof filtering, combine this with a
  network appliance / VPN block at the router.
- **"All" lists can't be exhaustive.** New/obscure search engines, private
  SearXNG instances, and freshly-registered adult domains may slip through. Add
  them to the relevant file as you find them; the feed handles bulk adult
  coverage automatically.
- **Large hosts file → slower DNS.** The adult feed adds ~77k entries, which the
  Windows DNS Client processes more slowly. A local DNS sinkhole would remove
  this overhead but is a larger rewrite.
- Runtime artifacts (log + caches) live in `C:\Program Files\StraitJacket\`:
  `straitjacket.log`, `feed_cache.txt`, `safesearch_cache.txt`.
