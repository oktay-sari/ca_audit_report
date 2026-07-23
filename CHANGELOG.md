# Changelog

## v0.17.4 (2026-07-23)

### Changed - least-privilege Graph scopes (external review feedback)
- **`Application.Read.All` is no longer requested.** Live-tenant / name-resolution runs now request only **`Policy.Read.All`** and **`Directory.Read.All`** (both read-only). Confirmed against Microsoft Graph docs that `Directory.Read.All` can read service principals, so the broader `Application.Read.All` was redundant. Easier to approve in security-sensitive tenants.
- **No more tenant-wide service-principal enumeration.** The resolver previously did `GET /servicePrincipals?$top=999` (paging every SP in the tenant) to name apps. It now collects only the **app IDs referenced by the audited policies** and resolves each with a targeted `GET /servicePrincipals(appId='...')` - least data as well as least privilege. Well-known apps are still named offline.
- `Connect-CAGraph` takes an explicit read-only `-Scopes` set (default `Policy.Read.All` + `Directory.Read.All`) and prints the scopes it requests at sign-in.
- Behavior unchanged for users: `-Source Tenant` still auto-resolves names; it simply asks for two scopes instead of three. Docs (README, readme1, SECURITY, entry-point help) updated.

_Note: the scope reduction and targeted app lookup exercise only against a live tenant. Verified offline (lint, parse, offline run unchanged); a live `-Source Tenant -ResolveNames` smoke test is recommended before publishing._

## v0.17.3 (2026-07-23)

### Changed - name cache stored outside the tool/repo (external review feedback)
- **`ca-name-cache.json` now lives in a per-user application-data directory**, never next to the code: `%LOCALAPPDATA%\ca-audit` on Windows, `~/.local/share/ca-audit` (or the platform equivalent via `LocalApplicationData`) on macOS/Linux. Resolved display names / UPNs no longer sit inside the tool folder where a missing `.gitignore` could leak them. An explicit `-CompanionFile` is unaffected; the cache directory is created on demand.
- **Automatic migration:** a cache that older versions wrote into the tool's `data/` folder is read on first run and, on the next save, rewritten to the new location and the legacy in-repo copy is removed (with a clear console notice).

## v0.17.2 (2026-07-23)

### Changed - report wording scoped to Conditional Access (external review feedback)
The report no longer implies a tenant has *no* protection when it simply has no **Conditional Access** policy for a control - protections outside CA (Security Defaults, per-user MFA, the authentication-methods policy) are outside this tool's scope, and the wording now says so.

- **Baseline gap titles are scoped to Conditional Access.** e.g. "Legacy authentication not blocked" -> "**No Conditional Access policy blocks legacy authentication**"; "No policy requires MFA for all users" -> "**No Conditional Access policy requires MFA for all users**". Applied across all 18 baseline/cross-policy gap findings (CA-008/009/019/023-038) and their detail text ("No active policy ..." -> "No active Conditional Access policy ..."), plus the Reference tab summaries.
- **Platform Matrix limitations are now prominent** wherever its results appear: the matrix tab shows an amber **"Approximation - verify before acting"** banner stating plainly that a gap means *no CA policy supplies the control - not that the tenant is unprotected*, and explicitly listing what it ignores (device filters, location/risk, session controls) and does not see (Security Defaults, per-user MFA, auth-methods policy). The printable/PDF summary caveat carries the same scope note.
- Docs (README, readme1) rule descriptions scoped to match.

## v0.17.1 (2026-07-23)

### Fixed - baseline accuracy + security-reporting doc (external review feedback)
- **CA-028 no longer counts as a vacuous baseline pass.** When a tenant has **no active enforcing All-Users policy**, there is nothing from which Directory Synchronization Accounts would need to be excluded - so CA-028 now returns **Not Applicable** (informational) instead of `Good`/covered. N/A controls count toward **neither** the covered numerator **nor** the applicable-controls denominator, so an empty tenant reads as e.g. `0/17` rather than an inflated `1/18`. (Reported by external security review.) The Baseline Coverage scorecard renders these as an **N/A** pill; when an enforcing policy exists, CA-028 evaluates normally (Covered/Gap) and the denominator is unchanged.
- **SECURITY.md** private-reporting path no longer ships a dead `<security-contact>` placeholder; GitHub **Private vulnerability reporting** is now the single documented channel.
- Confirmed `.gitignore` in the repo covers `*.html`, `*.xlsx`, `ca-name-cache.json`, `generated-policies/`, and `mypolicies/` (restore it in any published fork where it went missing during a repo split).

## v0.17.0 (2026-07-23)

### Changed - removed Excel output; HTML report is the only output (drops the ImportExcel/EPPlus dependency)
The tool no longer produces an Excel workbook. The single output is now the self-contained interactive HTML report (with its printable/PDF summary). This **removes the ImportExcel dependency** and the EPPlus 4.5.3.2 library it bundles - an end-of-life (2019), unpatched component that is undesirable in a security tool. The HTML report is generated with **built-in PowerShell only**; there is no third-party report/spreadsheet dependency.

- **`-Format` parameter removed.** There is no Excel/HTML/Both choice anymore - the tool always writes the HTML report. `-OutputPath` now defaults to `.\CA-Policy-Audit.html`.
- **`-RawFlatten` parameter removed** (it only produced an Excel sheet).
- **Deleted `modules/Export-CAStyle.ps1`** (Excel styling + formula-injection helpers). `Export-CAReport.ps1` and `Export-CAOverview.ps1` are retained but now hold only the **row builders** the HTML report consumes (all `Export-Excel` / `Format-*Sheet` code removed). The report data is byte-for-byte unchanged - verified by diffing the generated HTML before/after (identical apart from pre-existing run-to-run ordering of a few Not-Evaluated rows).
- **Guided wizard** no longer asks for an output format; it produces the `.html` report and echoes the matching one-line command.
- **Security model unchanged for the report:** tenant-controlled strings are still HTML-escaped (double-escaped in the data island). The Excel formula-injection neutralization is gone along with Excel, since there is no longer a spreadsheet sink.
- **Cross-platform bonus:** removing EPPlus also removes the macOS `libgdiplus` limitations (logo embedding / column auto-size) that only ever affected the Excel path.
- Docs updated throughout (README, readme1, CLAUDE, SECURITY, RELEASE-CHECKLIST).

## v0.16.1 (2026-07-23)

### Docs
- **`readme1.md` guided-mode walkthrough.** Expanded the thin "Guided / interactive mode" paragraph (section 6) into a real walkthrough: a faithful sample wizard session (verified against the tool's actual prompts), an ordered breakdown of every question the wizard asks (including the advanced path), and why it's worth using even if you know the flags (validates as you go; echoes the equivalent one-line command for scripting).

## v0.16.0 (2026-07-23)

### Changed - HTML report visual refresh + "Security posture" band
- **Signature "Security posture" band** now leads the interactive report: a single segmented bar reading worst -> best (Critical/High/Medium/Low/Info/Good), a baseline-coverage chip, and a one-line verdict. It fills left->right on load (respects `prefers-reduced-motion`). Clicking a segment or legend entry filters the findings to that severity - reusing the exact same `RANKS`/`SEVHEX`/segment math as the printable summary, so the two views can never disagree.
- **Palette retied to the actual All Things Cloud brand** (sampled from the logo): accent is now ATC blue `#0070b0` (light) / `#4aa8e0` (dark) instead of the generic SaaS blue, with a `--brand-cyan` highlight. Applied consistently across all four theme token blocks (base, media-dark, and both `data-theme` overrides).
- **Typography treatment** (system fonts, still fully offline): eyebrows are now mono, uppercase, wider-tracked; big figures use tabular-nums. Personality via treatment, zero added network weight.
- **Summary tiles demoted** to a quieter secondary control strip beneath the posture band (smaller figures, left-aligned, tighter) - they remain clickable filters. The posture band is the one bold element; everything around it stays disciplined.
- Printable/PDF summary, light/dark themes, and all existing filters verified unchanged.

## v0.15.0 (2026-07-23)

### Added - All Things Cloud branding on the HTML report
- **Logo in the interactive report and printable/PDF summary.** The top bar now shows the ATC shield emblem on a white tile (reads on both light and dark themes); the printable summary / PDF header shows the full "ALL THINGS CLOUD" wordmark where it has room.
- **New `assets/` folder** holds the two prepared PNGs: `atc-logo-emblem.png` (shield, for the top bar) and `atc-logo-full.png` (wordmark, for the summary). `Export-CAHtmlReport` reads them at generation time and inlines them as base64 `data:` URIs, so the report stays **fully self-contained** (no network calls). If the asset files are absent, it falls back to the original "CA" shield, so the tool still runs.

## v0.14.2 (2026-07-23)

### Docs
- **`readme1.md`** — a comprehensive end-to-end user guide (what it does, what/how it checks, offline vs live-tenant mode, every parameter, all output tabs and how to read them, remediation-policy generation, automation/scheduled runs, security model, troubleshooting, and a full 38-rule appendix).
- **`readme1.md` section 13 "Extending the tool"** rewritten from a stub into a full walkthrough: per-policy vs cross-policy checks, the complete `New-CAFinding` field/`ValidateSet` reference, a copy-paste example for each check kind, and the four-files-in-order recipe for a first-class baseline control (detection rule -> `Get-CABaselineMatcher` coverage entry -> `Get-CAGapPolicyDefinition` gap template / manual note -> `Get-CARuleReference` row), each with file + function + landmark line numbers, the missing-comma trap called out, and a verify checklist (lint / `ParseFile` / run against `sample-data`).
- **README `Running on Windows` section** — execution policy, `Unblock-File` (Mark of the Web), and module install for Windows PowerShell 5.1.

## v0.14.1 (2026-07-23)

### Added
- **Reference tab** (HTML) / **Reference sheet** (Excel) — a searchable, tenant-independent explanation of every rule id (CA-001..CA-038): its control name, a reader-friendly category (**Baseline control** / **Policy issue** / **Cross-policy gap** / **Directory data**), and a one-line "what it checks". So any `CA-033`-style callout elsewhere in the report is now explainable. New `modules/Get-CARuleReference.ps1` (self-contained; a test confirms every rule id has an entry).

### Changed
- **Wider HTML report (1440px) and the tab bar now wraps** instead of letting the last tab (e.g. Reference) fall off-screen.

### Fixed
- The Baseline Coverage **"Remediate gaps"** panel now shows an explicit **"Click to expand" / "Click to collapse"** hint (it was collapsible but gave no affordance).

## v0.14.0 (2026-07-22)

### Added - generate deploy-ready remediation policies for baseline gaps
The audit can now hand you the **policy that fixes each gap**, as ready-to-upload Conditional Access JSON. Strictly read-only w.r.t. the tenant - it only writes local files / offers browser downloads; nothing is ever sent to Graph.

- **New `modules/New-CAGapPolicy.ps1`** - a single validated template source of truth (14 templates) shared by both delivery paths. Each template conforms exactly to the documented `conditionalAccessPolicy` create schema (verified against the Graph docs), uses Microsoft well-known app/role ids, and is proven by a harness that builds it, structurally validates it, round-trips the JSON, imports it through the tool's own importer, and confirms the matching baseline rule flips to Pass.
- **PowerShell batch**: `-GenerateGapPolicies [-PolicyOutputFolder <dir>] [-BreakGlassGroupId <guid>]` writes one `<id>-<name>.json` per closable gap found in the audit, plus a `README.txt` (safety notes, upload steps, and the gaps that need manual remediation). No-BOM UTF-8 (portal-friendly).
- **HTML report**: the Baseline Coverage tab gains a **collapsible "Remediate gaps"** panel (click to expand) with a how-to-deploy explanation, a break-glass group-ID field, per-gap **Download** buttons, **Download all**, and the manual-only gaps listed with their reason. Generation is 100% client-side (Blob download, no network) and produces JSON byte-identical to the PowerShell writer.
- **Safety model**: default state **Report-only** (enforces nothing - cannot lock anyone out); a supplied break-glass group is injected into `excludeGroups`; without one, files are Report-only + name-marked `[ADD BREAK-GLASS EXCLUSION BEFORE ENABLING]`, and building an `enabled` (On) policy is refused. 4 gaps that can't be a clean single policy (CA-019 risk/P2, CA-028 dir-sync exclusion, CA-034 ToU, CA-035 MDCA) get a manual note instead.

### Changed
- **Baseline is now 18 controls (was 16); 38 rules (was 37).** `CA-009` (block device code flow) is promoted from a Security Check to a Baseline Coverage control (it belongs with its sibling CA-030, and Microsoft ships it as a managed policy). New `CA-038` (Should-Have, Low): require a compliant/hybrid-joined device for all users.

## v0.13.4 (2026-07-22)

### Changed
- **Expanded the test/staging keyword list** (used by `CA-020` and the baseline "covered by a test policy" flag) with `tst`, `testing`, `staging`, `dev`, and `uat`. Full list: `test`, `tst`, `testing`, `tmp`, `temp`, `poc`, `demo`, `draft`, `pilot`, `sandbox`, `staging`, `dev`, `uat`. Still whole-word and case-insensitive, so common names stay clean (verified: "Device", "Developer", "Latest", "Contested", "Demonstrable", "Production" do not match).

## v0.13.3 (2026-07-22)

### Added
- **Baseline Coverage flags when a covering policy looks like a test/staging policy.** If a control is only "covered" by a policy whose name matches the test keyword list (`test`, `tmp`, `temp`, `poc`, `demo`, `draft`, `pilot`, `sandbox` — whole-word, case-insensitive), the row's **Action** column now surfaces `[!] Coverage relies on a policy that looks like a test/staging policy (…) — confirm production coverage does not depend on it.` So a baseline satisfied only by a `TEST -` policy (often scoped to a tiny test group) is called out at a glance instead of being buried. The keyword list is now a single shared helper (`Test-CATestPolicyName`) used by both this flag and `CA-020`, so they can't drift.

## v0.13.2 (2026-07-22)

### Changed (performance)
- **Dropped the per-role member-count Graph fetch in baseline membership context.** It made one Graph call per targeted directory role — a policy targeting the full privileged-role set could balloon to dozens of sequential calls ("Fetching active member counts for N directory role(s)…"), adding 15–30+ seconds to a live run for little value: a role-targeted policy is correctly scoped to that role by definition, and the count was caveat-heavy (active-only, not PIM-eligible). **Roles are still named** (resolved offline, instant); only the `~N active assignments` suffix is gone. Group member counts (a genuine scope signal, and far fewer calls) are unchanged. Removed `Get-CARoleMembershipEnrichment` / `Get-CARoleEnrichment` / `$script:RoleEnrichment`.

## v0.13.1 (2026-07-22)

### Changed (rules)
- **The MFA baseline rules no longer count risk-gated policies** — `CA-023` (all users), `CA-024` (Azure management), `CA-025` (guests), and `CA-029` (admins). A policy that requires MFA but is scoped by a risk condition (`userRiskLevels` / `signInRiskLevels`) only enforces MFA for risky sign-ins, not unconditionally, so it no longer satisfies these baselines on its own (and is no longer listed under "Covered by"). Each rule's matcher entry was updated in lockstep (shared `$script:CAIsRiskGated` helper) so the naming stays consistent. A tenant whose only MFA for a given population is risk-based will now see that control as a **Gap** or **Covered (scoped)** rather than fully covered; proper unconditional MFA policies still count. Verified against a mixed policy set: the risk-gated policy is credited to no baseline, while genuine per-population MFA policies remain covered.

## v0.13.0 (2026-07-22)

### Added — Baseline Coverage now names the policies and grades scope
- **Covered controls name the covering policies** (with a count), e.g. *"Covered by: CA004 - Require MFA for all users; CA001 - ... (2 policies)."* — in the Details of both the HTML and Excel Baseline Coverage tabs.
- **Three-state coverage**: `Covered` (green) / `Covered (scoped)` (amber) / `Gap` (red). A requirement whose only enforcing policy is scoped to specific groups/roles/users (where All-users was expected) is flagged **Covered (scoped) — verify intended population**, rather than counted as fully covered or dismissed as a gap. The scorecard counts **fully covered** only; scoped are reported separately in the banner ("N fully covered … M covered but scoped").
- **Report-only near-miss on gaps**: when no active policy covers a requirement but a **Report-only** policy would, the gap notes *"A Report-only policy would cover this if promoted to On: X."*
- **Membership context (with `-ResolveNames`, informational — never changes the verdict)**: covering/scoped policies list their targeted principals with counts — groups (`~N members`, dynamic flagged), directory roles (`~N active assignment(s)`), and named users — with an explicit caveat that counts are point-in-time and don't resolve nested/dynamic membership, guests, or PIM-eligible role assignments. Fully offline-safe: with no enrichment, names are shown without counts and everything else still works.

Implementation: a post-processor (`modules/Invoke-CABaselineCoverage.ps1`, `Update-CABaselineCoverage`) enriches the `(baseline check)` findings after the rule engine runs, via a single matcher table (control predicate + expected population per requirement). **The 16 baseline rules are untouched** — a before/after regression proved zero Pass/Fail drift. CA-019 (dual-risk) and CA-028 (inverse-exclusion) don't fit the "covered by a policy" model and keep a simple covered/gap state. The Graph enrichment (read-only) was extended to fetch **included**-group membership (was exclusion-only) and **role** active-assignment counts; `Clear-CAResolverState` wipes the new role store too.

## v0.12.4 (2026-07-22)

### Changed (HTML report)
- **Summary tiles now stack the number above the label, centered** (e.g. `42` on top, `CHECKS` beneath) instead of inline/left-aligned. Side effect: the "Baseline covered" value (`7 / 16`) no longer wraps, so the tiles are more compact and uniform.

## v0.12.3 (2026-07-22)

Post-release code + security review (3 parallel review agents + automated scans: PSScriptAnalyzer, syntax parse, `.psd1` validation, injection/secret/read-only greps). Verdict: no Critical/High issues. Fixes applied:

### Changed (rules)
- **`CA-001` and `CA-003` now recognize device- and app-based grants as security controls.** Their "is this a security policy?" gate previously counted only `mfa`/`block`/`compliantDevice`/`authenticationStrength`/`passwordChange`. It now also includes `domainJoinedDevice` (Hybrid-joined), `approvedApplication`, and `compliantApplication` (app protection / MAM). So an Off/Report-only policy whose only grant is a managed-device or app-protection control is now flagged by CA-001 (Info), and CA-003 now catches location exclusions on those grants too. Session-only / no-grant policies are still skipped.

### Changed (HTML report)
- **Critical findings now have their own dashboard tile** (shown only when there are Critical findings, clickable to filter), and the printable summary's verdict + "At a glance" now surface Critical alongside High. Dashboard/summary grids auto-fit so the extra tile/box flows cleanly.
- **The printable summary's "N issues" headline now excludes Info-level fails** (e.g. Off / Report-only policies), so informational findings no longer inflate the issue count. They still appear in the severity-distribution bar and the findings table. (Dashboard High/Medium tiles already excluded them.)

### Security hardening (defensive; none were exploitable)
- **Raw Flatten headers are now neutralized.** `Protect-CAExcelRow` covers row *values*; the `-RawFlatten` sheet turns JSON property *paths* into column headers, so a hostile export key like `=HYPERLINK(...)` could reach a header cell (written as text, never evaluated, so not exploitable — but it was the one tenant-string-to-cell path skipping the neutralizer). Header names now pass through `Protect-CAExcelValue`.
- **`-ExcludePattern` gets a 2s regex match-timeout** (compiled `[regex]` with `IgnoreCase`), so a pathological operator-supplied pattern can't hang on a hostile displayName (ReDoS). Clear error on timeout.
- Documented that the Platform Matrix footer's leading static text is load-bearing for injection safety (the one direct `.Value` cell write).

### Fixed (docs / comments)
- Entry-point `Get-Help` `.DESCRIPTION` said "**29** security rules" — corrected to **37**, and the tab list now includes all produced tabs (Baseline Coverage, Platform Matrix, CA Policy Groups, Group Membership).
- Reworded stale "NotApplicable (e.g. an Off policy)" comments (Off now emits Info/Fail; the `NotApplicable` handling is dormant/defensive).
- Documented the `-TenantId` script-scope / dot-sourcing dependency in code and `CLAUDE.md`.

## v0.12.2 (2026-07-21)

### Added
- **Tenant safety pre-check for live mode.** Before reading any tenant data, the tool prints the signed-in tenant (organization name, tenant id, account). When a **cached / existing Graph session** would be reused silently (the wrong-tenant risk for admins who work across tenants), it now asks you to **confirm the tenant** first (default **No**); decline and it signs out of the cached session and does a fresh interactive sign-in. A fresh interactive sign-in (where you pick the account yourself) shows the banner without an extra prompt.
- **`-TenantId <guid>` parameter.** The tenant you expect to connect to. When supplied, the tool verifies the signed-in tenant matches and **aborts on mismatch** instead of prompting — ideal for non-interactive / scheduled runs. Still read-only (adds only `Get-MgContext` and `Disconnect-MgGraph`; no write scopes or writes).

### Changed
- **Inactive policies (Off / Report-only) are now Info, not High.** An Off or Report-only policy enforces nothing, so `CA-001` reports both as **Info** severity with a `Fail` status (a real finding, but lowest severity so they never inflate the High/Medium counts). Genuine gaps that an inactive policy leaves open are still caught by the baseline-existence rules, so nothing is hidden.
- **`CA-020` (test policy left enabled in production) is now Medium**, down from High.
- **Inactive policies are tinted.** In the **Policy Overview** and **CA Policy Groups** tabs (HTML + Excel), rows for policies in **Off** (light red) or **Report-only** (light amber) state get a subtle full-row background tint so they are easy to spot. The bold State cell keeps its own colour on top. New `Add-CAStateRowTint` helper (expression conditional-format, added after the State-cell formatting so it keeps a lower priority).
- **Renamed the "Security Findings" tab / Excel sheet to "Security Checks"** (HTML + Excel) — it lists automated checks (both passing and failing), so "findings" read as misleading. Internal ids and rule logic are unchanged.
- **Severity-tinted checks (HTML).** The **Security Checks** tab now gives each row a light background matching its severity (High red / Medium amber / Low yellow / Info blue-grey / Good green), on top of the existing left-edge stripe. HTML only.
- **Policy Overview is the first tab** in the HTML report (and the default view), ahead of Security Checks.
- **Dashboard "Findings" tile renamed to "Checks".** It counts every check run (issues + passing + n/a), so it was easy to confuse with the printable summary's "issues" number (failing checks only). "Checks" makes the total explicit; e.g. `Checks 41 = 29 issues + 12 passing`.
- **Uniform report typography.** All table headers and cell data in the HTML report now render at a single 12px size, and the "Affected"/policy columns drop the monospace styling so every column uses the same UI font. The light-blue info balloons are unchanged.

### Fixed
- **Info balloons had no space above them.** The banner's top margin collapsed through the panel's borderless top edge; the panel is now a block formatting context (`display: flow-root`), so the gap renders.
- **Printable summary now spans multiple pages.** The preview container was `display: flex`, and flex items do not fragment across print pages, so long summaries were clipped to one sheet. In print it is now `display: block` (with `break-inside` guards on logical blocks), so the summary paginates. Removed the "one page" wording from the button and preview bar.
- **Removed "Maester" references from user-facing output and docs.** The Baseline Coverage tab note now reads "Microsoft + community baseline" (matching the Excel export), and the README rule tables drop the "Maester" cross-reference column and reword the baseline description. (Historical CHANGELOG entries are left as-is.)

### Plumbing
- `NotApplicable` support is wired through the Security Checks tab (HTML + Excel), the Checks tile total, the `N/A` status pill, and an `n/a` count in the console/Excel summaries. It is dormant for now (no rule emits `NotApplicable`), ready for any future rule that needs it.

## v0.12.1 (2026-07-21)

### Fixed
- **Live-tenant mode dropped policies and left group names unresolved.** `Get-CAPolicySetFromGraph` fetched policies as objects that `Invoke-MgGraphRequest` returns as hashtables; the shared `ConvertTo-CleanPolicy` only handled `PSCustomObject`, so a hashtable fell into its enumerable branch and was destroyed (empty `id`, null `conditions`). That dropped policies from the report and, because name resolution reads GUIDs from `conditions.users.*`, left groups unresolved. Now the tenant fetch retrieves raw JSON and `ConvertFrom-Json`s it, producing the exact same `PSCustomObject` shape as the file path. `ConvertTo-CleanPolicy` also now handles `[IDictionary]` explicitly (before the enumerable check) as defense-in-depth.

## v0.12.0 (2026-07-21)

### Added
- **Live-tenant mode** via a new `-Source` parameter (`Files` default, or `Tenant`). `-Source Tenant` fetches all Conditional Access policies directly from Microsoft Graph (paged) — no manual export — auto-resolves names + Tier 2 enrichment, and uses the real organization display name in the report header. New `modules/Import-CAGraph.ps1` (`Get-CAPolicySetFromGraph`, `Get-CATenantName`).
  - **Strictly read-only.** Only `*.Read.All` scopes are requested; only read operations are issued (`GET`, plus the `directoryObjects/getByIds` read lookup); no `New-/Set-/Update-/Remove-Mg*` anywhere. Delegated interactive sign-in — no client secret or certificate is stored. The tool never writes to the tenant.
  - Shared read-only `Connect-CAGraph` (used by both the policy fetch and name resolution, so you sign in once).
  - The interactive wizard gains a first choice: **exported JSON files** vs **live tenant**.
- Shared `ConvertTo-CAPolicySet` (extracted from `Import-CAPolicySet`) normalizes policies identically for the file and tenant paths.

### Notes
- Live-tenant mode was validated end-to-end with a mocked Graph (paged fetch, `-ExcludePattern`, tenant name, full report); validate against a real tenant with `-Source Tenant`. The read-only guarantee is asserted by a grep in `RELEASE-CHECKLIST.md`.

## v0.11.3 (2026-07-21)

### Changed
- **Friendly "nothing to evaluate" messages.** When there are no Conditional Access policies to analyze, the tool now prints a clear, actionable message instead of a raw exception/stack trace. Covers: empty folder, folder not found, JSON files present but none are CA policies (points out that each needs a `conditions` block and a `state`), every policy excluded by `-ExcludePattern`, and an invalid `-ExcludePattern` regex — each with a next step and a pointer to "How to Export CA Policies". Unexpected errors still surface normally; interactive mode already re-prompts.

## v0.11.2 (2026-07-21)

### Added
- `SECURITY.md` — security policy, threat model, data-handling notes (name cache / reports contain UPNs), output-safety hardening summary, and private vulnerability-reporting instructions.
- `RELEASE-CHECKLIST.md` — pre-release verification steps (lint, pure-ASCII, syntax, functional run, security regression tests, interactive smoke test, no-sensitive-data check, version/docs).
- README **Security** section linking both.

## v0.11.1 (2026-07-21)

Pre-release hardening pass (security + correctness review).

### Security
- **Excel/CSV formula injection fixed.** A tenant-controlled string starting with `= + - @` (or a leading tab/CR/LF) was written into the workbook as a **live formula** (e.g. a policy `displayName` of `=HYPERLINK(...)`), which would execute when the auditor opened the report. Such values are now neutralized (prefixed with `'`) before writing. New `Protect-CAExcelValue` / `Protect-CAExcelRow` in `Export-CAStyle.ps1`, applied to every Excel sheet. The HTML report was already safe (double-escaped).
- README note that `ca-name-cache.json` and the reports contain directory display names/UPNs and should be treated as sensitive.

### Fixed
- **Platform Matrix** used an invalid grant token `appProtectionPolicy`; corrected to `compliantApplication`, so "Require app protection policy" grants are detected (were shown as "no control").
- **Cross-Reference** risk notes now recognize `domainJoinedDevice`, `approvedApplication`, and `compliantApplication` (previously only `compliantDevice` counted as a device-control bypass).
- **Excel** severity coloring gained the missing `Info` tier.
- **HTML report is now pure ASCII** — it previously emitted mojibake for the sort arrows and separators on Windows PowerShell 5.1 (BOM-less file with literal glyphs). Also fixed a no-op `U+2028/U+2029` escape in the JSON sanitizer.
- **HTML printable summary** guards its arrays against PowerShell 5.1 single-element `ConvertTo-Json` unwrapping.
- **HTML accessibility**: sort headers and expandable rows are keyboard-operable (`tabindex`/`role`/`aria-expanded`/keydown + visible focus ring); `role="tabpanel"` on the panel; focus moves into the summary dialog on open.
- **HTML UX**: search caret no longer jumps to the end while typing; search and severity filters reset per tab; responsive topbar (no horizontal scroll on narrow screens).
- Excel package is disposed in a `finally` if a builder throws mid-pipeline.
- `_RuleTemplate.ps1` suppresses its intentional unused-parameter warning.

### Changed
- **Entire tool is now pure ASCII** (removed em dashes and other non-ASCII from comments/strings across all modules and rules).
- Added `PSScriptAnalyzerSettings.psd1` documenting the intentionally-disabled style rules; `Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1` now reports **zero findings**.

## v0.11.0 (2026-07-21)

### Added
- **Guided interactive setup.** New `-Interactive` switch, and the wizard also **auto-launches when `-JsonFolder` is omitted** (now optional) — so running the tool with no arguments walks the user through the options. New `modules/Invoke-CAInteractive.ps1`.
  - **Quick path** (default): asks only for the policy folder and output format, saving the report to the current working folder.
  - **Advanced path**: adds output location, Graph name resolution, companion file, exclude pattern, and raw-flatten sheet (recurse is offered only when subfolders with JSON are detected; the companion prompt is skipped when a `MigrationTable.json` is auto-detected).
  - Validates the folder (must contain policy JSON), shows a review/confirm step, and prints the **equivalent command line** for scripting the same run later.
  - `q` at any prompt cancels; end-of-input (redirected/empty stdin) cancels gracefully; a non-interactive host with no `-JsonFolder` errors with usage instead of hanging.

## v0.10.0 (2026-07-21)

### Added
- **Interactive HTML report** via a new `-Format` parameter (`Excel` default, `Html`, or `Both`) and `modules/Export-CAHtml.ps1`. A single self-contained `.html` file (inline CSS + JS, no network calls) with the same tabs as Excel, plus clickable summary tiles, live search, sortable columns, severity filter chips, expandable findings, a printable one-page summary (Print / Save PDF), tooltips on controls, and a light/dark toggle that follows the OS theme.
  - Reuses the exact same row-builder functions as the Excel export (`Build-*`, `ConvertTo-OverviewRow`), so the two formats never drift. A data-driven JS engine renders every tab from column metadata.
  - **Security:** embedded data is JSON with `<`, `>`, `&` escaped to `\uXXXX` (prevents `</script>` breakout), and the page HTML-escapes every value at render time — tenant content (e.g. a policy displayName containing markup) can never execute.
  - Output extension is derived from `-OutputPath`; `-Format Both` writes the `.xlsx` and `.html` side by side.
- `.gitignore` now excludes `*.html` (report output may contain tenant data).

## v0.9.1 (2026-07-21)

### Changed
- **Baseline Coverage now covers 16 controls** (was 14): CA-019 (risk-based policies present) and CA-028 (directory sync accounts) are folded in. Both are now marked `(baseline check)` so they appear on the Baseline Coverage scorecard as Covered/Gap, in addition to Security Findings.
- CA-028 gained a **Pass branch** ("Directory sync accounts properly handled") so it always emits one finding — previously it only reported on failure, so it was absent from clean tenants. Its failure now carries the offending policy names in the detail text (the Affected-policies column reads `(baseline check)` like the other baseline rows).

### Fixed
- CA-019's failure branch was still marked `(cross-policy check)`, so on tenants where risk-based policies were incomplete the control dropped off the Baseline Coverage scorecard. Both branches now use `(baseline check)`, making the scorecard a consistent 16 rows regardless of tenant.

## v0.9.0 (2026-07-21)

### Added
- **Platform Matrix tab** — an approximate effective-control grid (Windows/macOS/iOS/Android/Linux × Browser-unmanaged / Browser-managed / Apps-unmanaged / Apps-managed) for access to Office 365, computed from policy targeting and grant controls. Cells show the effective control (MFA, Compliant, Blocked, App protection, or "No control (password only)" = gap) plus the driving policies.
  - Scoped to **All-users** O365 policies; **group-scoped** O365 policies are listed in a footer instead of merged in.
  - Excludes policies gated by conditions the matrix cannot model — **named location, sign-in/user risk, and authentication-flow** (device code / auth transfer) — so a conditional block (e.g. "block from country X", "block device-code flow") no longer falsely shows "Blocked" everywhere. Their count is noted in the footer.
  - Prints an explicit "approximation only — not a substitute for Entra What-If" caveat; also does not evaluate device filters or session controls.
  - New helpers in `Export-CAReport.ps1`: `Test-CAPolicyTargetsO365`, `Test-CAPolicyAllUsers`, `Test-CAPolicyPlatform`, `Test-CAPolicyClient`, `Test-CAPolicyMatrixEligible`, `Get-CAPolicyEffect`, `Get-CACellEffect`, `Build-PlatformMatrixRow`, `Get-CAGroupScopedO365Policy`.

## v0.8.1 (2026-07-21)

### Added
- **CA Policy Groups tab** — one row per policy showing its included and excluded principals (users, groups, roles, guests) spread across columns, with a scope summary and include/exclude counts. Principals carry a type tag (e.g. `(Group)`, `(Role)`); when a policy has more than 12 per side the last column collapses to "+N more" (full lists remain on Policy Details). Names resolved via the usual chain (well-known / cache / companion / Graph).

### Fixed
- Policy state colouring now uses exact match (`Equal`) instead of `ContainsText`, so "On" no longer mis-colours "Report-only" rows. New shared `Add-CAStateFormatting` helper, used by both Policy Overview and CA Policy Groups.

## v0.8.0 (2026-07-21)

### Added
- **Excel export overhaul** — new shared styling module `modules/Export-CAStyle.ps1`:
  - **Explicit column widths** on every tab, replacing ImportExcel's `-AutoSize` (which silently fails on macOS / hosts without libgdiplus and left columns at default width). Fixes column sizing cross-platform and removes the auto-fit warnings from the report path.
  - **Title + subtitle banner** on each tab (rows 1-2), navy title band + slate subtitle; the table now starts at row 3.
  - **Multi-row freeze panes** that pin the banner + header row **and** the key left columns (policy name / finding #) while scrolling.
  - **Banded rows** and a full-scale severity palette (Critical > High > Medium > Low > Good, plus Pass/Fail/Covered/Gap) applied via conditional formatting.
- **Baseline Coverage tab** — generated from the baseline existence rules (CA-023-037): Status (Covered/Gap), Control, Priority, Details, Action; gaps sorted first by severity.
- **Group Membership tab** (only with `-ResolveNames`) — from Tier 2 enrichment: group name, include/exclude usage counts, dynamic vs assigned, live member count, and deleted/empty notes.

### Changed
- `Get-ExcelColumnName` moved to `Export-CAStyle.ps1` (shared).
- The `-RawFlatten` sheet no longer uses `-AutoSize`.

## v0.7.0 (2026-07-21)

### Added
- **`-ExcludePattern <regex>` parameter** to drop policies before analysis by `displayName` (case-insensitive regex). Use `-ExcludePattern 'TEST'` to exclude test/staging policies so the report reflects the enforced production posture. Excluded count is reported; the run errors clearly on an invalid regex or if the pattern would exclude every policy. Off by default. Implemented in `Import-CAPolicySet` and surfaced on the entry point.
- Comment-based help for `-CompanionFile` and `-ExcludePattern` on the entry point (`-CompanionFile` help was missing since v0.6.0).

## v0.6.1 (2026-07-21)

### Changed
- **Smarter non-policy filter in the importer.** A JSON object is now treated as a CA policy only if it has a `conditions` block **and** a recognised CA state (`enabled`/`disabled`/`enabledForReportingButNotEnforced`). Previously any object with a `displayName` **or** `conditions` was accepted, so non-policy exports (group/role/named-location dumps, settings-catalog configs) in the same folder could be mis-imported. The importer now prints `Skipped N non-policy object(s)` for transparency. Real CA policies — including report-only and Off ones — are unaffected.

## v0.6.0 (2026-07-21)

### Added
- **Offline name resolution from a companion file** (`MigrationTable.json`). New `-CompanionFile <path>` parameter, plus auto-detection of a `MigrationTable.json` next to the policies (or in the parent folder). Resolves group/user GUIDs to real names with no Graph connection. Supports the IntuneManagement MigrationTable shape and a plain `{ "<guid>": "<name>" }` map. New resolution-chain step (4) in `Resolve-CAIdentity`; `Import-CACompanionName` in `Resolve-CAIdentities.ps1` (defensive parsing — warns and continues on any error).
- Synthetic `sample-data/MigrationTable.json` fixture (fabricated GUIDs/names) so the feature has offline sample data.

### Security / data handling
- Companion names are stored in a **separate in-memory map** and are **never written to `ca-name-cache.json`**.
- New `Clear-CAResolverState` wipes companion names and Tier 2 enrichment (group membership, location IP ranges) from memory after every run, invoked in a `finally` so it runs even on error/interrupt.
- The tool only **reads** the companion file; it never modifies or deletes the input.
- Because object GUIDs are globally unique, a companion match is always the correct object; a non-match stays unresolved (no cross-tenant/false names).

### Changed
- Importer skips any file named `MigrationTable.json` (companion map, not a policy).

## v0.5.0 (2026-07-21)

### Added
- **8 modern-control baseline rules (CA-030–CA-037)**, calibrated against the [kennethvs/cabaseline202510](https://github.com/kennethvs/cabaseline202510) MoSCoW priority. Each is a cross-policy existence check that passes when an enforced policy uses the control and (like CA-009) notes when a matching policy exists only in Report-only:
  - CA-030 Authentication transfer flow not blocked — **High** (Must Have; AiTM vector)
  - CA-031 Token protection (secureSignInSession) not deployed — Low (Could Have)
  - CA-032 Sign-in frequency not configured — Medium (Must Have)
  - CA-033 Persistent browser session not restricted — Medium (Must Have)
  - CA-034 Terms of Use not enforced — Info (Could Have)
  - CA-035 MDCA session control (cloudAppSecurity) not used — Info (Could Have)
  - CA-036 Exchange ActiveSync not blocked — Medium (Must Have; complements CA-008)
  - CA-037 MFA not required for device join/registration — Medium (Must Have)

### Changed
- Entry-point summary now counts rule files dynamically (`Rules evaluated: N`) instead of a hardcoded number, so it can no longer go stale.

### Notes
- Severities for the new rules were tuned so High/Medium track the baseline's Must-Have controls and Low/Info track its Could-Have controls.
- Validated against the full 49-policy baseline: all eight fire correctly in Report-only (with the not-enforced note) and pass once the controls are enforced.

## v0.4.0 (2026-07-21)

### Added
- **Tier 2 rules now evaluate with `-ResolveNames`** (previously always `NotEvaluated`):
  - **CA-016** — fetches exclusion-group membership: deleted group referenced as an exclusion → Fail (Critical); empty-but-existing → Pass (Low, advisory); populated → Pass with member count. Dynamic groups are flagged.
  - **CA-017** — inspects named-location IP ranges: any IPv4 range wider than /16, or a country-based trusted exclusion → Fail (High); all ranges /16 or tighter → Pass.
  - **CA-018** — compares actual membership of co-occurring exclusion groups: subset (nested) or ≥50% Jaccard overlap → Fail (Medium); disjoint → no finding.
- Enrichment store in `Resolve-CAIdentities.ps1` with accessors `Test-CAEnrichmentAvailable`, `Get-CAGroupEnrichment`, `Get-CALocationEnrichment`. `Invoke-GraphNameResolution` now captures location IP ranges/trust and fetches group membership (`Get-CAGroupMembershipEnrichment`).
- `Get-CidrPrefixLength` (CA-017) and `Measure-CAMembershipOverlap` (CA-018) helpers.

### Notes
- Membership and IP-range data are held in memory for the run only and are **not** persisted to the name cache (data sensitivity); an offline re-run reverts CA-016/017/018 to `NotEvaluated`.
- No new Graph scopes required — existing `Directory.Read.All` covers group-member reads.
- Offline behavior unchanged (zero regression on `sample-data`).

## v0.3.0 (2026-07-21)

### Changed
- **Cross-Reference tab overhaul** — the exclusion matrix now focuses on risk instead of dumping every exclusion:
  - Only principals excluded from 2+ policies are listed (external tenants always shown, since even one exclusion warrants a check).
  - Columns collapse to policies that carry a relevant exclusion; colliding short names get a `(2)` suffix.
  - New **Risk note** column: HIGH/MEDIUM rating by exclusion count, flags whether bypassed policies enforce MFA / Block / device compliance, and a verify-compensating-policy reminder for external partners.
  - "Exclusion count" column renamed to **Exclusions**.
- New internal helpers `Get-PolicyControlLabel` and `Get-ExclusionRiskNote` in `Export-CAReport.ps1`.

## v0.2.0 (2026-06-23)

### Added
- 7 Maester-inspired baseline existence rules (CA-023 through CA-029)
  - CA-023: MFA required for all users (MT.1007)
  - CA-024: MFA required for Azure management (MT.1008)
  - CA-025: MFA required for guest access (MT.1016)
  - CA-026: Compliant/hybrid device required for admins (MT.1014)
  - CA-027: Security info registration secured (MT.1011)
  - CA-028: Directory sync accounts properly excluded (MT.1020)
  - CA-029: MFA required for admin roles (MT.1006)
- Maester test ID cross-references in README rule table

## v0.1.0 (2026-06-23)

Initial release.

### Features
- **Policy Overview**: 16-column Excel tab matching consulting deliverable format
- **Policy Details**: Drill-down tab for large role/group/app lists
- **Security Findings**: 29 automated rules (26 static Tier 1, 3 Tier 2 stubs)
- **Not Evaluated**: Tier 2 findings that require Graph access displayed with priority and data requirements
- **Cross-Reference**: Exclusion matrix showing which principals bypass which policies
- **Offline mode**: 150 built-in Entra role IDs, 74 app IDs, all grant/session controls resolved without Graph
- **Online mode**: Optional `-ResolveNames` resolves all tenant-specific GUIDs via Microsoft Graph with name caching
- **Raw Flatten**: Optional `-RawFlatten` sheet dumps every JSON property path as a column
- **JSON format support**: Single-policy files, arrays, and Graph API `{value:[...]}` wrappers
- **OData stripping**: Removes `@odata.context` annotations automatically
- **Deduplication**: Same policy ID in multiple files keeps the most recent version
