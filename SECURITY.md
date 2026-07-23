# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for anything
that could expose or exploit users.

- Use GitHub **Private vulnerability reporting**: on the repository's **Security** tab, choose
  *Report a vulnerability*. This is the only supported private reporting channel.

Please include: affected version, a description, reproduction steps, and — for an
input-handling issue — a **sanitized** sample policy (no real tenant data). You can
expect an acknowledgement within a few business days.

## Supported versions

This is a single-branch tool; only the latest released version receives fixes.

| Version | Supported |
|---------|-----------|
| latest  | ✅        |
| older   | ❌        |

## What this tool is (and isn't)

The CA Policy Audit Tool is a **local, read-only command-line tool**. It:

- reads Conditional Access policy JSON **exports** you provide and produces a self-contained interactive HTML report;
- **never modifies** any policy, tenant, or directory object;
- optionally connects to Microsoft Graph **read-only** to turn GUIDs into names (`-ResolveNames`)
  or to fetch the policies live (`-Source Tenant`).

**Live-tenant access is strictly read-only.** It requests only `Policy.Read.All` and, for name
resolution, `Directory.Read.All` (`Application.Read.All` is **not** requested — `Directory.Read.All`
is sufficient to read service principals). It issues only read operations (HTTP `GET`, plus the
`directoryObjects/getByIds` lookup which is a read); and it contains no `New-/Set-/Update-/Remove-Mg*`
calls. Sign-in is delegated and interactive — no client secret or certificate is stored. The tool
never creates, modifies, or deletes anything in the tenant.

It is **not** a network service or multi-tenant application. Inputs such as `-JsonFolder`,
`-OutputPath`, `-CompanionFile`, and `-ExcludePattern` are supplied by the operator running
the tool on their own machine; the tool does not derive any file path or command from policy
content.

## Data handling

Conditional Access exports and the generated reports contain **sensitive tenant
configuration** (policy names, group/user names when resolved, UPNs). Treat them accordingly.

- **The report** (`.html`) contains resolved display names. Share only with authorized parties.
- **Name cache** (`ca-name-cache.json`) is written **only** when `-ResolveNames` is used and
  contains directory display names and UPNs. It lives in a **per-user application-data directory
  outside the tool/repo** (`%LOCALAPPDATA%\ca-audit` on Windows, `~/.local/share/ca-audit` on
  macOS/Linux) so resolved names never sit next to the code. A cache that older versions wrote
  into the tool's `data/` folder is migrated to this location automatically. Do not commit or
  share the cache.
- **Companion-file names** (`MigrationTable.json`) and **Graph group-membership data** are kept
  in memory for the run only, are **never** written to the cache, and are wiped from memory in a
  `finally` block when the run ends (including on error / Ctrl-C).
- **Microsoft Graph**: scopes requested are read-only — `Policy.Read.All` and, for name
  resolution, `Directory.Read.All` (only these two; `Application.Read.All` is not requested, and
  only the app IDs referenced by policies are resolved — no tenant-wide service-principal
  enumeration). No token, secret, or credential is ever logged or written to disk.

## Output-safety hardening

Because policy exports are attacker-influenceable data (a policy `displayName` can contain
anything), the tool neutralizes injection at the report boundary:

- **HTML / JS injection (XSS)** — the interactive HTML report is **double-escaped**: embedded
  data is serialized as JSON with `<`, `>`, `&` escaped to `\uXXXX` (preventing `</script>`
  breakout), and every value is HTML-escaped again at render time. The report is fully
  self-contained: no external scripts, styles, fonts, or network calls.

## No dynamic execution

The tool contains no `Invoke-Expression`/`iex`, no `Add-Type`/reflection from input, no dynamic
regex built from tenant data, and no shell/process execution. Rule files and `.psd1` data files
are shipped code loaded via dot-sourcing / `Import-PowerShellDataFile` (data only).

## Dependencies

- PowerShell 5.1+ (also runs on PowerShell 7 / macOS).
- `Microsoft.Graph.Authentication` (only for `-ResolveNames`).

The interactive HTML report is generated with built-in PowerShell only - no third-party
report/spreadsheet dependency.

Keep these up to date; report suspected issues in a dependency to that project directly.
