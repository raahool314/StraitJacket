# StraitJacket

A Windows service that blocks access to a list of websites for **every** user on
the machine. It starts automatically at boot, restarts itself if it fails, and
cannot be stopped by non-administrator users.

## How it works

Two enforcement layers, both re-applied **every 30 seconds** (so any tampering
is automatically reverted):

1. **Hosts file** — each blocked domain (and its `www.` variant) is pointed at
   `0.0.0.0` in `C:\Windows\System32\drivers\etc\hosts`.
2. **Windows Firewall** — the service resolves each domain to its real IPs by
   querying public DNS resolvers directly (1.1.1.1 / 8.8.8.8), *bypassing* the
   hosts file, then blocks those IPv4/IPv6 addresses with inbound + outbound
   firewall rules named `StraitJacket-Block`. This catches users who switch to
   a custom DNS server to evade the hosts file. Rules are only rebuilt when the
   resolved IP set changes.

The service runs as **LocalSystem**, installs under **Program Files** (not
writable by standard users), and is configured with a security descriptor that
lets only SYSTEM and Administrators start/stop/reconfigure it.

## Requirements

- Windows with .NET Framework 4.x (the in-box `csc.exe` is used to compile —
  **no .NET SDK needed**).
- An elevated (Administrator) PowerShell to install/uninstall.

## Install

```powershell
# from an elevated PowerShell, in this folder:
.\install.ps1
```

## Configure the blocklist

Edit one domain per line in:

```
C:\Program Files\StraitJacket\blocklist.txt
```

Then apply the change (as admin):

```powershell
sc.exe stop StraitJacket ; sc.exe start StraitJacket
```

(or just wait up to 30 seconds — the service re-reads the list on each pass.)

## Uninstall

```powershell
# from an elevated PowerShell, in this folder:
.\uninstall.ps1
```

## Files

| File                  | Purpose                                            |
|-----------------------|----------------------------------------------------|
| `src/StraitJacket.cs` | The Windows Service (hosts-file enforcement + loop).|
| `src/DnsResolver.cs`  | Direct-to-DNS resolver (bypasses the hosts file).  |
| `src/FirewallManager.cs` | Builds/clears the Windows Firewall block rules.  |
| `blocklist.txt`       | Domains to block (copied into Program Files).      |
| `install.ps1`         | Compile, install, harden, and start the service.   |
| `uninstall.ps1`       | Stop/remove the service and clean the hosts file.  |

## Notes & limitations

- The hosts + firewall combo covers DNS-based evasion and direct-IP access to
  the resolved addresses. It still does **not** stop a determined user who
  routes traffic through a **VPN or proxy** (which gives a different exit IP),
  or who reaches a site via a large CDN whose IPs rotate faster than the 30s
  refresh. For fully tamper-proof filtering, combine this with a network
  appliance / VPN block at the router.
- The runtime log is at `C:\Program Files\StraitJacket\straitjacket.log`.
