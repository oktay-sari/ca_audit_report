# CA Policy Audit Tool — Complete User Guide

A PowerShell tool that audits **Microsoft Entra Conditional Access (CA) policies** and turns them into a clear, actionable report — with a security scorecard, a recommended-baseline gap analysis, an exclusion cross-reference, and even **ready-to-deploy policies that fix the gaps it finds**.

It runs **fully offline** against exported policy JSON, or **live** against a tenant over Microsoft Graph (**strictly read-only** — it never changes anything). Output is a **self-contained interactive HTML report** (no network calls, works offline) with a printable one-page summary you can Save as PDF.

- Works on **Windows PowerShell 5.1** and **PowerShell 7** (Windows / macOS / Linux).
- No agent, no service, no data leaves your machine (offline mode makes zero network calls).
- 38 checks, an 18-control best-practice baseline, and one-click remediation policy generation.

---

## Table of contents

1. [What it does](#1-what-it-does)
2. [What it checks (and how)](#2-what-it-checks-and-how)
3. [Requirements & installation](#3-requirements--installation)
4. [Getting your policies in](#4-getting-your-policies-in)
5. [Quick start](#5-quick-start)
6. [Running modes in depth](#6-running-modes-in-depth)
   - [Offline (files) mode](#offline-files-mode)
   - [Live-tenant mode (read-only)](#live-tenant-mode-read-only)
   - [Name resolution](#name-resolution)
   - [Guided / interactive mode](#guided--interactive-mode)
7. [Every parameter](#7-every-parameter)
8. [The output — the report & how to read it](#8-the-output--the-report--how-to-read-it)
9. [Generating & deploying remediation policies](#9-generating--deploying-remediation-policies)
10. [Automation & scheduled runs](#10-automation--scheduled-runs)
11. [Security, privacy & the read-only guarantee](#11-security-privacy--the-read-only-guarantee)
12. [Troubleshooting](#12-troubleshooting)
13. [Extending the tool](#13-extending-the-tool)
14. [Appendix — full rule reference](#14-appendix--full-rule-reference)

---

## 1. What it does

Conditional Access is the front door to a Microsoft 365 / Entra tenant, but it's hard to reason about: policies overlap, exclusions pile up, "Report-only" policies enforce nothing, and it's easy to *think* you require MFA for everyone when you don't. This tool reads your policies and answers, in plain language:

- **What's wrong with the policies you have?** (misconfigurations, weak grants, risky exclusions, test policies left On)
- **What recommended controls are you missing?** (an 18-control best-practice baseline)
- **Who bypasses your policies?** (an exclusion cross-reference)
- **What actually protects Office 365, per platform?** (an approximate effective-control matrix)
- **How do I fix the gaps?** (it generates the missing policies as ready-to-upload JSON)

It is built for consultants doing tenant reviews and for admins hardening their own tenant. The report is designed to be handed to a client as a deliverable.

---

## 2. What it checks (and how)

### The checks

The tool runs **38 rules**, each producing a finding with a **severity** (`Critical` › `High` › `Medium` › `Low` › `Info`, plus `Good` for a passing baseline). Rules fall into four categories (the report's **Reference** tab explains every rule id):

| Category | Meaning | Where it appears |
|---|---|---|
| **Baseline control** | A recommended control that *should exist* (18 of these) | **Baseline Coverage** tab |
| **Policy issue** | Something wrong with an *existing* policy | **Security Checks** tab |
| **Cross-policy gap** | A gap spanning several policies | **Security Checks** tab |
| **Directory data** | Needs a live Graph lookup (group members / location IP ranges) — only with `-ResolveNames` | **Security Checks** / **Not Evaluated** |

The **18-control baseline** is drawn from Microsoft guidance + community best practice (calibrated against the [kennethvs/cabaseline202510](https://github.com/kennethvs/cabaseline202510) Must/Should/Could-Have priorities). It covers the essentials — MFA for all users / admins / guests / Azure management, block legacy auth & device-code flow, secure security-info registration, sign-in frequency, persistent browser, token protection, and more.

> A complete list of all 38 rules with one-line explanations is in the [Appendix](#14-appendix--full-rule-reference) and, at report time, in the **Reference** tab/sheet.

### How it checks

- **Static analysis (always, offline).** Every policy's JSON — conditions, grant controls, session controls, state — is parsed and evaluated against the rules. No network, no tenant access. This produces every finding except the three "Directory data" checks.
- **Graph enrichment (optional, `-ResolveNames`).** Read-only Graph calls resolve GUIDs to names and fetch the extra directory data the three Tier-2 checks need (group membership, named-location IP ranges). This turns their `Not Evaluated` results into real Pass/Fail, and adds membership context to the baseline coverage.
- **Name resolution chain.** GUIDs (users, groups, roles, apps, locations) become readable names via, in order: built-in well-known maps (150 roles, 74 apps, all controls) → a name cache from a previous run → an offline companion `MigrationTable.json` → live Graph (with `-ResolveNames`) → otherwise a `type: <guid-prefix>… (unresolved)` placeholder.

Everything is **read-only**. In live mode the tool requests only `*.Read.All` scopes and issues only read operations — it never creates, modifies, or deletes anything.

---

## 3. Requirements & installation

- **PowerShell 5.1+** — Windows PowerShell 5.1 (built into Windows) or [PowerShell 7](https://aka.ms/powershell). Windows, macOS, and Linux are all supported.
- **No third-party report dependency** — the interactive HTML report is generated with built-in PowerShell only. Nothing to install for the report itself.
- **Microsoft.Graph.Authentication** — only needed for `-ResolveNames` or `-Source Tenant`.

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser   # only for live/resolve modes
```

### Windows setup notes

Two Windows defaults to expect (not tool bugs):

```powershell
# 1) Allow scripts for this session (or launch with -ExecutionPolicy Bypass)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned

# 2) If you downloaded the folder as a .zip, clear the "blocked" flag once:
Get-ChildItem -Recurse -Filter *.ps1 | Unblock-File
```

The HTML report is a single self-contained file, so it looks and behaves identically on Windows, macOS, and Linux — just open it in any browser.

---

## 4. Getting your policies in

You only need this for **offline (files) mode**. Live-tenant mode fetches them for you.

**From the Entra portal** — Conditional Access → Policies → open a policy → **Download policy file** (one JSON per policy). Put them all in a folder.

**From Graph PowerShell** (read-only):

```powershell
Connect-MgGraph -Scopes "Policy.Read.All"

# One file per policy:
$policies = Invoke-MgGraphRequest -Method GET -Uri "v1.0/identity/conditionalAccess/policies"
foreach ($p in $policies.value) {
    ($p | ConvertTo-Json -Depth 10) | Set-Content ("{0}.json" -f ($p.displayName -replace '[^\w\-]','_'))
}

# …or everything in one file:
$policies | ConvertTo-Json -Depth 10 | Set-Content "all-ca-policies.json"
```

**From Graph Explorer** — `GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies`, save the response. The tool handles the `{ "value": [...] }` wrapper automatically.

Accepted shapes: one policy per file, an array of policies, or the Graph `{value:[…]}` wrapper — mix and match in one folder. If the folder also contains an IntuneManagement **`MigrationTable.json`**, names resolve offline automatically (see [Name resolution](#name-resolution)).

---

## 5. Quick start

```powershell
# Offline — audit a folder of exported policy JSON
.\Invoke-CAPolicyAudit.ps1 -JsonFolder .\my-policies

# Live — read straight from the tenant (read-only sign-in)
.\Invoke-CAPolicyAudit.ps1 -Source Tenant -OutputPath .\Client-CA-Audit.html

# No arguments — a guided wizard walks you through the options
.\Invoke-CAPolicyAudit.ps1
```

Open `CA-Policy-Audit.html` (double-click → opens in any browser, fully offline).

---

## 6. Running modes in depth

### Offline (files) mode

The default. Reads exported JSON, runs entirely on your machine, makes **zero network calls**.

```powershell
.\Invoke-CAPolicyAudit.ps1 -JsonFolder .\exported-policies
.\Invoke-CAPolicyAudit.ps1 -JsonFolder .\exported-policies -Recurse          # include subfolders
.\Invoke-CAPolicyAudit.ps1 -JsonFolder .\exported-policies -ExcludePattern 'TEST|PILOT'
```

Tenant-specific GUIDs (users, groups, named locations) show as placeholders unless you add name resolution. Use `-ExcludePattern <regex>` to drop test/staging policies so the report reflects your enforced production posture (it's matched case-insensitively against each policy's `displayName`, reports how many it excluded, and errors if it would exclude everything).

### Live-tenant mode (read-only)

```powershell
.\Invoke-CAPolicyAudit.ps1 -Source Tenant -OutputPath .\Client-CA-Audit.html
```

Fetches all CA policies straight from Microsoft Graph — no manual export — auto-resolves names, and produces the report. **Strictly read-only:** only `*.Read.All` scopes, only read operations, delegated interactive sign-in (no stored secret or certificate). It never writes to the tenant.

**"Which tenant am I on?"** Before reading anything, the tool prints the signed-in tenant (organization, tenant id, account). If a **cached Graph session** would be silently reused, it asks you to **confirm the tenant** first (default **No**) — so if you work across tenants you can't audit the wrong one by accident. For unattended runs, pass `-TenantId <guid>` to assert the expected tenant — the tool verifies the match and aborts on mismatch instead of prompting:

```powershell
.\Invoke-CAPolicyAudit.ps1 -Source Tenant -TenantId 1234abcd-89ef-4567-89ab-1234567890ab
```

Live mode implies `-ResolveNames`, so names and the Tier-2 checks are fully resolved.

### Name resolution

By default (offline, no companion file) GUIDs appear as placeholders. Three ways to get real names:

1. **`-ResolveNames`** — connects read-only to Graph and resolves every GUID to a display name. Resolved names are cached to `ca-name-cache.json` in a **per-user app-data directory outside the tool/repo** (`%LOCALAPPDATA%\ca-audit` on Windows, `~/.local/share/ca-audit` on macOS/Linux) so *future* runs can be offline and still show names — sensitive names never sit next to the code. (An older cache that lived in the tool's `data/` folder is migrated to the new location automatically.) This also enables the three **Tier-2 checks** (CA-016/017/018) by fetching group membership and named-location IP ranges (held in memory for the run only, never written to the cache).

   ```powershell
   .\Invoke-CAPolicyAudit.ps1 -JsonFolder .\exported-policies -ResolveNames
   ```

   Required scopes: `Policy.Read.All` and `Directory.Read.All` (read-only). `Application.Read.All` is **not** needed — service principals are read under `Directory.Read.All`, and only the app IDs referenced by policies are resolved (no tenant-wide service-principal enumeration).

2. **Companion `MigrationTable.json`** — if your export shipped with one (the IntuneManagement tool writes one next to the policies), the tool resolves group/user GUIDs to names **with no Graph connection at all**. Auto-detected in the policy folder (or its parent); or point at one with `-CompanionFile <path>`. A MigrationTable only maps the GUIDs of the export it came with (object GUIDs are globally unique, so a match is always correct); companion names are used for that run only and never written to the cache.

3. **Nothing** — placeholders like `group: 1a2b3c… (unresolved)`. The audit still works; only the human-readable names are missing.

> **Handle names as sensitive.** `ca-name-cache.json` and the generated report contain display names and UPNs. `ca-name-cache.json` and `*.html` are git-ignored by default — don't commit or share them without intent.

### Guided / interactive mode

If you'd rather not remember parameters, run the tool with **no arguments** (or an explicit `-Interactive`) and it walks you through a short wizard:

```powershell
.\Invoke-CAPolicyAudit.ps1
```

At every prompt, **Enter** accepts the shown default and **q** quits. A typical offline session looks like this (what you type is after each prompt):

```text
  +--------------------------------------------+
  |   CA Policy Audit - guided setup           |
  +--------------------------------------------+
  Answer the prompts (Enter accepts the default, q quits).

Audit from:
    1) Exported JSON files (default)
    2) Live tenant (Microsoft Graph, read-only sign-in)
  Choose 1-2: 1

Folder with CA policy JSON exports: .\my-policies
  Found companion name map (MigrationTable.json) - group names will resolve offline.

Configure advanced options? [y/N]: n

  Review:
    Source        : C:\work\my-policies
    Report        : .\CA-Policy-Audit.html

Proceed with these settings? [Y/n]: y

  Tip - run the same audit non-interactively next time with:
    .\Invoke-CAPolicyAudit.ps1 -JsonFolder 'C:\work\my-policies' -OutputPath '.\CA-Policy-Audit.html'
```

**What the wizard asks, in order:**

1. **Audit from** — `1` exported JSON files, or `2` a live tenant (read-only Graph sign-in). Choosing the tenant skips the folder question and signs you in read-only when the audit runs.
2. **Folder** (files mode only) — the folder holding your policy JSON. It's validated on the spot (must exist and contain `.json` policies) and re-asks if not. If a companion `MigrationTable.json` sits alongside, it's detected here and group names resolve offline.
3. **Configure advanced options?** — answer `n` for the common case. Answer `y` to also be asked, in this order: output file path (`.html`); (files mode) recurse into subfolders; (files mode) resolve names via Graph; (if resolving) a companion name-map file; and an exclude regex (e.g. `TEST`) to drop staging policies.
4. **Review + proceed** — it echoes your choices and asks to confirm before running.

Two things make the wizard worth using even if you know the flags:

- It **validates as you go** (bad folder, no policies found, out-of-range menu choice) instead of failing after launch.
- It prints the **equivalent one-line command** for exactly what you chose — copy it into a script or scheduled task so the next run is non-interactive.

---

## 7. Every parameter

| Parameter | Type | Default | What it does |
|---|---|---|---|
| `-Source` | String | `Files` | `Files` reads exported JSON from `-JsonFolder`; `Tenant` fetches live from Graph (read-only) and auto-resolves names |
| `-JsonFolder` | String | (prompted) | Folder of CA policy JSON files (Files mode). If omitted and interactive, the wizard runs |
| `-Interactive` | Switch | Off | Force the guided wizard (also auto-runs when `-JsonFolder` is omitted) |
| `-OutputPath` | String | `.\CA-Policy-Audit.html` | Path for the interactive HTML report |
| `-ResolveNames` | Switch | Off | Connect read-only to Graph to resolve GUIDs → names and enable the Tier-2 checks |
| `-TenantId` | String | (off) | Expected tenant GUID for live mode; verifies the match and aborts on mismatch (no prompt) — for unattended runs |
| `-CompanionFile` | String | (auto-detect) | Path to a `MigrationTable.json` for offline GUID resolution |
| `-ExcludePattern` | String | (off) | Regex (case-insensitive) matched against `displayName`; matching policies are excluded before analysis |
| `-GenerateGapPolicies` | Switch | Off | Also write ready-to-upload remediation policy JSON for each closable baseline gap (local files only) |
| `-PolicyOutputFolder` | String | `generated-policies` next to the report | Where the generated gap policies go |
| `-BreakGlassGroupId` | String | (off) | Emergency-access group GUID to exclude on every generated gap policy |
| `-Recurse` | Switch | Off | Search subfolders for JSON files |

---

## 8. The output — the report & how to read it

The tool produces one **self-contained interactive HTML report** — a single file with no network calls, all values HTML-escaped, that opens in any browser and works fully offline. It has clickable summary tiles, a **Security posture** overview, live search, sortable columns, severity filters, expandable findings, a printable one-page summary (**Summary** button → Print / Save PDF), and a light/dark toggle.

### Reading the summary

At the top of the HTML report, six tiles: **Checks** (all checks run) · **High** · **Medium** · **Passing** · **Not evaluated** · **Baseline covered (N/18)** — plus a **Critical** tile if any Critical findings exist. Click a tile to filter. The printable **Summary** gives a one-page executive view: issue count, severity distribution, top priority actions, and baseline gaps.

### The tabs

| Tab | What it shows | How to read it |
|---|---|---|
| **Policy Overview** | One row per policy: state, who/what it applies to, grant & session controls, logic | State is colour-coded (green On, amber Report-only, red Off); Off/Report-only rows are tinted. Expand a row for included/excluded principals, locations, platforms, client apps |
| **Security Checks** | Every finding, sorted by severity | Columns: finding · risk · status · affected policy · why it matters · recommendation. Rows are tinted by severity; expand for detail. Filter with the severity chips or the summary tiles |
| **Baseline Coverage** | The 18-control scorecard | Three states: **Covered** (green), **Covered (scoped)** (amber — control exists but only for specific groups/roles, *verify the population*), **Gap** (red). Each row **names the policies covering it**, notes if only a Report-only policy would, and (in the panel at the top) offers **one-click remediation downloads** for the gaps |
| **Platform Matrix** | Approximate effective control on Office 365 | Platforms × Browser/Apps × unmanaged/managed. Cells show MFA / Compliant / Blocked / App protection / "No control (password only)" = gap. **Approximation only** — reflects All-users O365 policies, ignores device filters & session controls; verify with Entra What-If |
| **Cross-Reference** | Exclusion matrix | Rows = principals excluded from **2+** policies (external tenants always shown); "X" marks an exclusion. The **Risk note** column rates it and says what the bypassed policies enforce |
| **CA Policy Groups** | Included/excluded principals per policy | One row per policy, principals spread across columns with type tags and counts |
| **Not Evaluated** | Checks that need `-ResolveNames` | Each shows what data is needed and why. Re-run with `-ResolveNames` to evaluate them |
| **Group Membership** *(with `-ResolveNames`)* | Live membership of groups used in policies | Include/exclude usage, dynamic vs assigned, member count, deleted/empty flags |
| **Reference** | What every rule id (CA-NNN) checks | Searchable: rule · control · category · one-line explanation — so any "CA-033" callout elsewhere is explainable |

---

## 9. Generating & deploying remediation policies

The audit doesn't just find gaps — it can hand you the **policy that fixes each one**, as ready-to-upload Conditional Access JSON. This is **strictly read-only** with respect to your tenant: it writes local files / offers browser downloads and **never sends anything to Graph**.

**From the HTML report** — the Baseline Coverage tab's **"Remediate gaps"** panel (click to expand): optionally enter your break-glass group ID, then use per-gap **Download** buttons or **Download all**. 100% client-side, works offline.

**From PowerShell:**

```powershell
.\Invoke-CAPolicyAudit.ps1 -Source Tenant -GenerateGapPolicies `
    -PolicyOutputFolder .\generated-policies `
    -BreakGlassGroupId <your-emergency-access-group-guid>
```

This writes one `<id>-<name>.json` per closable gap, plus a `README.txt` with deploy steps and notes for the gaps that need manual setup.

### Safety model — important

- **Report-only by default.** Generated policies are created in `enabledForReportingButNotEnforced` state. A Report-only policy **logs what would happen but enforces nothing**, so it *cannot lock anyone out*.
- **Break-glass.** Supply `-BreakGlassGroupId` (or the field in the HTML panel) and your emergency-access group is excluded on every policy. **Omit it** and files stay Report-only, their name is marked `[ADD BREAK-GLASS EXCLUSION BEFORE ENABLING]`, and the tool **refuses to generate any On-state policy**. Always exclude your break-glass accounts before enforcing anything.
- **Manual gaps.** Four gaps can't be a clean single policy — risk-based (needs Entra ID P2 + tuning), dir-sync exclusion (an edit to existing policies), Terms of Use (needs an existing ToU object), MDCA (needs MDCA configured). These come with a note instead of a file.

### Deploying one

1. Download the `.json`.
2. Entra portal → **Conditional Access → Policies → Upload policy file**.
3. Choose it and keep the state on **Report-only**.
4. Review the impact in **Insights & Reporting** for a few days.
5. Add your break-glass exclusion (if you didn't supply it) and only then switch it **On**.

---

## 10. Automation & scheduled runs

The tool runs unattended cleanly — everything can be passed on the command line, and it prints progress plus a summary you can capture.

**A scheduled offline audit** (e.g. of a nightly policy export) — no Graph, no prompts:

```powershell
.\Invoke-CAPolicyAudit.ps1 -JsonFolder C:\CAExports\daily `
    -OutputPath C:\Reports\CA-Audit.html -ExcludePattern 'TEST'
```

**A scheduled live audit** — use `-TenantId` so it asserts the right tenant and never blocks on a confirmation prompt. This needs a non-interactive Graph auth context (e.g. a managed identity or app registration you've signed in with the read scopes); the tool itself only ever reads:

```powershell
.\Invoke-CAPolicyAudit.ps1 -Source Tenant -TenantId <expected-guid> `
    -OutputPath \\share\reports\CA-$(Get-Date -Format yyyyMMdd).html
```

Tips for automation:
- **Pin the tenant** with `-TenantId` — the interactive "confirm this tenant?" prompt is skipped when the signed-in tenant matches, and the run aborts (rather than auditing the wrong tenant) on mismatch.
- **Non-interactive hosts** — if there's no sign-in context and the run needs one, it exits with a clear message rather than hanging.
- **Output handling** — the report contains UPNs/display names; write it somewhere access-controlled. `*.html` / `ca-name-cache.json` are git-ignored so they won't be committed by accident.
- **Exit / summary** — the console prints `Findings: X fail, Y pass, Z n/a` and the High/Critical counts; capture stdout for a run log.
- **CI use** — the whole tree passes PSScriptAnalyzer with the repo settings, so it's safe to lint in a pipeline: `Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1`.

---

## 11. Security, privacy & the read-only guarantee

- **Read-only, always.** Offline mode makes no network calls at all. Live mode requests only `Policy.Read.All` and `Directory.Read.All` (not `Application.Read.All`), issues only read operations (GET + the read-only `directoryObjects/getByIds` lookup), and contains **no** write cmdlets or scopes. The tenant confirmation and `-TenantId` guard exist so you never point it at the wrong tenant.
- **Your data stays local.** Nothing is uploaded. Generated remediation policies are files on your disk that *you* upload — the tool never deploys them.
- **Sensitive artifacts** — `ca-name-cache.json` and the report contain display names / UPNs; the name cache is cleared of companion-file names and Tier-2 membership after each run, and `*.html` / `ca-name-cache.json` / `generated-policies/` are git-ignored.
- **Output-safety hardening** — the HTML report escapes all values (no `</script>` breakout, everything HTML-escaped, no external resources under a strict offline model), so tenant-controlled strings can never execute.

See **[SECURITY.md](SECURITY.md)** for the full threat model and how to report a vulnerability.

---

## 12. Troubleshooting

| Symptom | Fix |
|---|---|
| *"running scripts is disabled on this system"* (Windows) | `Set-ExecutionPolicy -Scope Process RemoteSigned`, or launch with `powershell -ExecutionPolicy Bypass -File .\Invoke-CAPolicyAudit.ps1 …` |
| Scripts blocked after unzipping (Windows) | `Get-ChildItem -Recurse -Filter *.ps1 \| Unblock-File` |
| Names show as `… (unresolved)` | Add `-ResolveNames` (Graph), or a `MigrationTable.json` companion file, or accept placeholders offline |
| Live mode prompts for the wrong tenant | It's asking because a **cached** Graph session exists — answer **No** to re-sign-in, or pass `-TenantId <guid>` |
| Several checks say **Not Evaluated** | Those are Tier-2 (need directory data) — run with `-ResolveNames` |
| A generated policy is rejected on upload | Send the portal error — the templates match the documented Graph schema, but tenant-specific quirks can occur |

---

## 13. Extending the tool

New checks are added by dropping a file into `rules/` — the engine finds it automatically, so you never edit a central list to register a rule. Everything else (which files, which line, what the fields mean) is spelled out below.

> **Line numbers are approximate.** They drift as the code changes, so each step also names the **function** and a **landmark line to search for**. Open the file, jump near the line, then find the landmark. All paths are relative to the project root.

### 13.1 Two kinds of check

| Kind | Function name prefix | Called | Use it when |
|---|---|---|---|
| **Per-policy** | `Test-CARule-XXX` | once **per policy** — you get one `$Policy` | The problem lives inside a single policy (a bad exclusion, a weak grant, a test policy left on). |
| **Cross-policy** | `Test-CACrossRule-XXX` | once for the **whole set** — you get `$Policies` (an array) | The question is "does *any* policy do X?" — i.e. a baseline control that *should exist* somewhere. |

The engine that dispatches both lives in `modules/Invoke-CAFindings.ps1`, in `Invoke-CAFindingSet` (near line 81: `& $rule.Name -Policy $policy` for per-policy, near line 93: `& $rule.Name -Policies $Policies` for cross-policy). You don't touch it — it discovers every `rules/CA-*.ps1` file and calls whichever function name it finds.

### 13.2 The `New-CAFinding` fields

Every check returns its result by calling `New-CAFinding` (defined in `modules/Invoke-CAFindings.ps1`, line 151). The fields and their allowed values:

| Field | Required | Allowed values | Notes |
|---|---|---|---|
| `-Id` | yes | `'CA-XXX'` | Must match the file name and the reference entry (13.5). |
| `-Name` | yes | any string | Short title shown in the report row. |
| `-Severity` | yes | `Critical`, `High`, `Medium`, `Low`, `Info`, `Good` | `Good` = the control is present/passing. |
| `-Requires` | yes | `static`, `group-membership`, `named-location-detail`, `role-assignment` | `static` = works fully offline. The others need `-ResolveNames` (a live Graph lookup) to be meaningful. |
| `-PolicyName` | yes | the policy's `displayName`, **or** the literal `'(baseline check)'` | `'(baseline check)'` routes the finding onto the **Baseline Coverage** scorecard instead of the per-policy list. |
| `-Detail` | yes | any string | What was found and why it matters. Shown in the report. |
| `-Remediation` | yes | any string | What to do about it. |
| `-Status` | yes | `Pass`, `Fail`, `NotEvaluated`, `NotApplicable` | `NotEvaluated` = the rule needed data it didn't have (e.g. `-ResolveNames` was off). |

A rule may return nothing (just `return`) when the policy isn't relevant, one finding, or several.

### 13.3 Add a per-policy check (the common case)

1. **Copy the template:** `rules/_RuleTemplate.ps1` → `rules/CA-039-YourShortName.ps1`. Pick the next free `CA-0NN` number (the appendix in §14 lists what's taken — currently up to CA-038).
2. **Rename the function** to `Test-CARule-039`.
3. **Implement it.** A complete example — flag any enabled policy that grants access with no controls at all:

   ```powershell
   # Rule: CA-039 - Enabled policy grants access with no controls
   # Type: per-policy | Tier: static
   function Test-CARule-039 {
       [CmdletBinding()]
       param([Parameter(Mandatory)] $Policy)

       if ($Policy.state -ne 'enabled') { return }          # only judge live policies
       $g = $Policy.grantControls
       $hasGrant   = $g -and @($g.builtInControls | Where-Object { $_ }).Count -gt 0
       $hasSession = $Policy.sessionControls -and (
           $Policy.sessionControls.PSObject.Properties.Value | Where-Object { $_ })
       if ($hasGrant -or $hasSession) { return }            # it enforces something - fine

       return New-CAFinding -Id 'CA-039' `
           -Name 'Enabled policy with no grant or session controls' `
           -Severity 'Medium' `
           -Requires 'static' `
           -PolicyName $Policy.displayName `
           -Detail 'This policy is On but sets neither a grant control nor a session control, so it enforces nothing.' `
           -Remediation 'Add a grant control (MFA / compliant device / block) or a session control, or turn the policy off.' `
           -Status 'Fail'
   }
   ```

That's the whole change for a per-policy check. Add a reference row (§13.5) so the report can explain it, run the checks (§13.6), and you're done.

### 13.4 Add a baseline control (shows on the scorecard **and** is remediable)

A baseline control is a "this *should* exist somewhere" check. Making it first-class means touching **four files in order** so the whole pipeline knows about it: the detection rule, the coverage matcher (names the policy that satisfies it), the gap template (generates a fix), and the reference (explains it).

Worked example: **CA-040 — require MFA for the "register or join device" *and* the browser client.** (Illustrative; the real CA-037 already covers device registration.)

**Step 1 — the detection rule** — `rules/CA-040-YourShortName.ps1`, cross-policy, model it on `rules/CA-036-ActiveSyncNotBlocked.ps1`:

```powershell
# Rule: CA-040 - <control> not enforced
# Type: cross-policy | Tier: static
function Test-CACrossRule-040 {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Policies)

    $active = @($Policies | Where-Object { $_.state -eq 'enabled' })
    $covered = $false
    foreach ($p in $active) {
        # ...your condition: does this policy satisfy the control?...
        if ($true) { $covered = $true; break }
    }

    if ($covered) {
        return New-CAFinding -Id 'CA-040' -Name '<control> is enforced' `
            -Severity 'Good' -Requires 'static' -PolicyName '(baseline check)' `
            -Detail 'At least one active policy enforces <control>.' `
            -Remediation 'Keep enabled.' -Status 'Pass'
    }
    return New-CAFinding -Id 'CA-040' -Name '<control> not enforced' `
        -Severity 'Medium' -Requires 'static' -PolicyName '(baseline check)' `
        -Detail 'No active Conditional Access policy enforces <control>. <why it matters>.' `
        -Remediation 'Create or enable a policy that <does X>.' -Status 'Fail'
}
```

The `PolicyName = '(baseline check)'` marker is what puts it on the **Baseline Coverage** tab.

**Step 2 — the coverage matcher** — so the scorecard can *name the policy that satisfies the control* (not just say "covered"). Edit `modules/Invoke-CABaselineCoverage.ps1`, function `Get-CABaselineMatcher` (line 121). Add one entry to the hashtable it returns — put it near the last entry, `'CA-038' = @{ ... }` (line 196). Each entry has a `Population` (which users the control should target) and a `Control` scriptblock returning `$true` when a given policy `$p` satisfies it:

```powershell
'CA-040' = @{ Population = 'AllUsers'; Control = {
    param($p)
    # same test as the rule, but for ONE policy $p - return $true if it satisfies the control
    $actions = @($p.conditions.applications.includeUserActions | Where-Object { $_ })
    if ('urn:user:registerdevice' -notin $actions) { return $false }
    & $script:CAHasMfaOrStrength $p          # shared helper: policy requires MFA or an auth strength
} }
```

`Population` is one of `AllUsers`, `Guests`, `AdminRoles`, `Any`. Two shared helper scriptblocks are available inside `Control`: `& $script:CAHasMfaOrStrength $p` (policy requires MFA or an authentication strength) and `& $script:CAIsRiskGated $p` (policy is gated on user/sign-in risk — usually you *exclude* those from a plain-MFA baseline, as CA-023/024/025/029 do).

**Step 3 — the gap template** — so the report can hand the user a deploy-ready JSON fix. Edit `modules/New-CAGapPolicy.ps1`, function `Get-CAGapPolicyDefinition` (line 66). Add an `[ordered]@{ ... }` block to the array — model it on the CA-023 entry (line 72). The `Build` scriptblock returns the policy object exactly as the Graph `POST /identity/conditionalAccess/policies` API expects it (no `id`, no timestamps — those are read-only):

```powershell
[ordered]@{
    Id = 'CA-040'; FileName = 'CA-040-require-mfa-device-registration.json'
    Name = 'CA-040 - Require MFA to register or join a device'
    Build = {
        param($State, $DisplayName)
        [ordered]@{
            displayName = $DisplayName; state = $State
            conditions  = [ordered]@{
                applications = [ordered]@{ includeUserActions = @('urn:user:registerdevice') }
                users        = [ordered]@{ includeUsers = @('All') }
            }
            grantControls = [ordered]@{ operator = 'OR'; builtInControls = @('mfa') }
        }
    }
}
```

Don't set `state` or add `excludeGroups` yourself — the writer (`New-CAGapPolicyObject`) forces `enabledForReportingButNotEnforced` (Report-only) by default, refuses to emit an `enabled` policy unless you passed `-BreakGlassGroupId`, and injects the break-glass exclusion for you. For privileged-role scopes use `@($script:CAGapAdminRoleIds)` (the 15 admin role GUIDs, line 33); for the Azure-management app use `$script:CAGapAzureMgmtAppId` (line 52).

*If the control can't be auto-generated* (it needs a pre-existing object or a P2 licence — like Terms of Use or risk policies), skip the template and instead add a one-line note to `Get-CAGapPolicyManualNote` in the same file (line 309), keyed by the rule id, e.g. `'CA-040' = 'Requires <X> to exist first - create it in the portal, then ...'`. Those notes surface in the report's remediation panel. See the existing CA-019/028/034/035 entries (lines 313-316) for the pattern.

**Step 4 — the reference row** — so the **Reference** tab can explain the rule id to anyone reading the report. Edit `modules/Get-CARuleReference.ps1`, the `$ref` array (line 21). Add a **comma-terminated** row after the current last one (CA-038, line 59):

```powershell
@('CA-040', 'MFA required to register or join a device', 'Baseline control', 'No active Conditional Access policy requires MFA for the register/join device user action, so a stolen password could enroll a device.'),
```

Category is one of `'Baseline control'`, `'Policy issue'`, `'Cross-policy gap'`, `'Directory data'`. **Gotcha:** the inner arrays *must* be comma-separated. A missing comma makes PowerShell unroll every element into single characters and the tab fills with 150+ garbage rows. Also make sure the row you added is *not* the last element if you leave a trailing comma — match the existing style (every row but the last ends in a comma).

### 13.5 Reference row for a plain (non-baseline) check

Even a per-policy check from §13.3 should get a Step-4 reference row so the report can explain it — just use category `'Policy issue'` (or `'Cross-policy gap'` / `'Directory data'` as appropriate). This is the only extra file a non-baseline check touches.

### 13.6 Verify your change

Run these from the project root before committing:

```powershell
# 1. Parse + lint the files you touched (zero findings expected)
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1

# 2. Confirm the new rule file parses (catches the missing-comma trap)
[System.Management.Automation.Language.Parser]::ParseFile(
    "$PWD/rules/CA-040-YourShortName.ps1", [ref]$null, [ref]$null)

# 3. Run the whole tool against the bundled sample data and open the report
.\Invoke-CAPolicyAudit.ps1 -JsonFolder ./sample-data -OutputPath /tmp/test.html
```

Then spot-check the output: your rule id appears on the **Reference** tab (Step 4 worked), a baseline control shows on the **Baseline Coverage** tab with the covering policy named (Step 2 worked), and — if you added a gap template — `-GenerateGapPolicies -BreakGlassGroupId <guid>` writes a `CA-040-*.json` you can import into a test tenant (Step 3 worked). The Reference tab is generated straight from `Get-CARuleReference`, so if a rule id shows up in a report row but *not* on that tab, you forgot Step 4.

---

## 14. Appendix — full rule reference

Severity is the typical gap/finding severity; several rules are `Good` when passing. Category: **Baseline control** (should exist), **Policy issue** (problem with an existing policy), **Cross-policy gap** (spans policies), **Directory data** (needs `-ResolveNames`).

| Rule | Control | Category | What it checks |
|---|---|---|---|
| CA-001 | Security policy in Report-only or Off | Policy issue | An Off/Report-only security policy is enforcing nothing — flagged informational to confirm it's intentional |
| CA-002 | Include/exclude set overlap (self-negation) | Policy issue | The same principal is both included and excluded, so the policy can never apply |
| CA-003 | Location exclusion on a security grant | Policy issue | A policy requiring MFA/device excludes locations, so those sign-ins skip the control |
| CA-004 | Admins on plain MFA, not authentication strength | Policy issue | Admin policy uses "Require MFA" rather than a phishing-resistant authentication strength |
| CA-005 | Deprecated grant control (approved app alone) | Policy issue | Relies on the deprecated approvedApplication grant on its own |
| CA-006 | Same principal excluded from many policies | Cross-policy gap | One principal excluded from several policies — a broad blind spot |
| CA-007 | All users / All apps with no MFA or device grant | Policy issue | A broad policy requiring neither MFA nor a managed device |
| CA-008 | Legacy authentication not blocked | Cross-policy gap | No active Conditional Access policy blocks legacy auth (can't do MFA; top password-spray vector) |
| CA-009 | Device-code flow not blocked | Baseline control | No active Conditional Access policy blocks the device-code auth flow (a growing phishing technique) |
| CA-010 | Browser missing from MFA client app types | Policy issue | An MFA policy that omits "browser" leaves browser sign-ins uncovered |
| CA-011 | Platform exclusion creates a coverage gap | Policy issue | A device-platform exclusion leaves those platforms without the control |
| CA-012 | Grant operator OR weakens layered controls | Policy issue | Combining controls with OR means any one satisfies the policy (weaker than AND) |
| CA-013 | External principal excluded, no compensating policy | Cross-policy gap | An external/guest principal excluded from multiple policies with nothing else covering it |
| CA-014 | No session controls on an admin policy | Policy issue | An admin policy sets no sign-in frequency / persistent-browser control |
| CA-015 | Break-the-glass group audit | Cross-policy gap | Reviews emergency-access group exclusions for consistency and intent |
| CA-016 | Exclusion group empty or deleted | Directory data | A group used as an exclusion is empty or deleted — a stale-exclusion backdoor |
| CA-017 | Named location may be overly broad | Directory data | A trusted-location exclusion spans a wide IP range or a whole country |
| CA-018 | Duplicate or nested exclusion groups | Directory data | Exclusion groups overlap or nest, widening the exclusion more than intended |
| CA-019 | Risk-based policies present | Baseline control | Active policies cover both user risk and sign-in risk (Identity Protection, needs P2) |
| CA-020 | Test policy left enabled in production | Policy issue | An enabled policy whose name looks like a test/staging policy (test, dev, uat, pilot…) |
| CA-021 | Session-only policy (no grant controls) | Policy issue | A policy with only session controls and no grant — confirm it's intentional |
| CA-022 | Policy targeting no applications | Policy issue | A policy that includes no applications never applies |
| CA-023 | MFA required for all users | Baseline control | The most fundamental baseline: MFA for all users on a broad app scope |
| CA-024 | MFA required for Azure management | Baseline control | MFA for the Azure portal / ARM API / Microsoft admin portals |
| CA-025 | MFA required for guest access | Baseline control | MFA for guest and external (B2B) users |
| CA-026 | Managed device required for admins | Baseline control | A compliant or hybrid-joined device required for admin roles |
| CA-027 | Security-info registration secured | Baseline control | The "Register security information" action protected with MFA or a trusted location |
| CA-028 | Directory sync accounts handled | Baseline control | Directory Synchronization Accounts excluded from enforcing policies |
| CA-029 | MFA required for admin roles | Baseline control | MFA (or authentication strength) required for admin directory roles |
| CA-030 | Authentication transfer flow blocked | Baseline control | The auth-transfer flow blocked — defends against Adversary-in-the-Middle session hijack |
| CA-031 | Token protection deployed | Baseline control | Token protection (secure sign-in session) enforced to bind tokens to the device |
| CA-032 | Sign-in frequency configured | Baseline control | A sign-in frequency session control that forces periodic reauthentication |
| CA-033 | Persistent browser session restricted | Baseline control | Persistent browser sessions disabled (mode = never) so cookies don't survive close |
| CA-034 | Terms of Use enforced | Baseline control | A Terms of Use acceptance required via a grant control |
| CA-035 | MDCA session control used | Baseline control | Sessions routed through Microsoft Defender for Cloud Apps (Conditional Access App Control) |
| CA-036 | Exchange ActiveSync blocked | Baseline control | Exchange ActiveSync (a legacy protocol) blocked |
| CA-037 | MFA required for device registration | Baseline control | MFA for the register/join device action, so a stolen password can't enroll a device |
| CA-038 | Managed device required for all users | Baseline control | Should-Have: a compliant/hybrid-joined device for all users (blocks BYOD/guests — use with care) |

---

*Built to be read by a human. If a report row ever confuses you, the **Reference** tab explains the rule, and the **Baseline Coverage** tab tells you exactly which policy covers a control — or hands you one to fix it.*
