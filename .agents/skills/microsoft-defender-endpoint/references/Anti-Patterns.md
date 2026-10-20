# Defender Query Anti-Patterns (AP-Q1 — AP-Q16)

A catalogue of common anti-patterns in KQL query design for Microsoft Defender for Endpoint Advanced Hunting. Use as a rejection checklist.

> **Hypothesis anti-patterns** (AP-H1–H5): see `kusto-query-language/references/Hypothesis-Anti-Patterns.md`.

---

## AP-Q1: The Dragnet

**Pattern**: Query so broad it returns thousands of results in any environment.

```kql
// BAD: catches every DNS query to any external domain
DeviceNetworkEvents
| where ActionType == "DnsQueryResponse"
| where RemoteUrl !endswith ".internal.example"
```

```kql
// GOOD: targets specific DNS pattern from intelligence
let c2_patterns = dynamic(["solarspotlight.example", "updateservice-cdn.example"]);
DeviceNetworkEvents
| where ActionType == "DnsQueryResponse"
| where RemoteUrl has_any (c2_patterns)
| summarize QueryCount = count() by DeviceName, RemoteUrl, bin(Timestamp, 1h)
```

**Why it fails**: 50 000 results is not a detection — it is a full table scan.

**Fix**: Add specificity from the intelligence source. Use `has_any` with known indicators, filter to relevant asset groups, set meaningful thresholds.

---

## AP-Q2: The Copy-Paste

**Pattern**: Query copied from a blog or template without adaptation.

```kql
// BAD: generic ransomware query
DeviceFileEvents
| where FileName endswith ".encrypted"
| where ActionType == "FileCreated"
```

```kql
// GOOD: adapted for the specific family + environment
DeviceFileEvents
| where FileName matches regex @"\.(cl0p|cllp)$"
| where FolderPath has_any ("POS", "PointOfSale", "RetailData", "Backups")
| where ActionType == "FileCreated"
| summarize EncryptedCount = count() by DeviceName, FolderPath, bin(Timestamp, 5m)
| where EncryptedCount > 10
```

**Why it fails**: Generic queries do not leverage the intelligence that justified the hunt; they miss specific indicators and generate noise.

**Fix**: Build from raw intelligence — extract specific indicators and behavioural patterns and shape the query around them.

---

## AP-Q3: The Black Box

**Pattern**: No comments, no rationale, arbitrary-looking filter values.

```kql
// BAD
DeviceProcessEvents
| where ProcessCommandLine matches regex @"[A-Za-z0-9+/]{50,}={0,2}"
| where InitiatingProcessFileName in ("cmd.exe", "powershell.exe")
| where Timestamp > ago(14d)
```

```kql
// GOOD
// Hunt: Base64-encoded PowerShell payloads matching loader profile
// Regex matches base64 blocks > 50 chars (typical encoded command length)
// Parent processes limited to cmd/powershell as documented in kill chain
// 30d window covers active campaign period
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe")
| where ProcessCommandLine matches regex @"[A-Za-z0-9+/]{50,}={0,2}"
| extend DecodedLength = strlen(ProcessCommandLine)
| where DecodedLength > 200
| project Timestamp, DeviceName, AccountUpn, ProcessCommandLine, InitiatingProcessFileName
```

**Why it fails**: A reviewer cannot trust a query they cannot understand; intent must be reverse-engineered.

**Fix**: Use inline comments AND the rationale field. Every non-trivial filter must be explained.

---

## AP-Q4: The Time Bomb

**Pattern**: No time bound or excessively long lookback that will time out.

```kql
// BAD: no time filter — scans entire table
DeviceLogonEvents
| where LogonType == "RemoteInteractive"

// BAD: 365-day lookback — extremely slow, exceeds Defender retention
DeviceLogonEvents
| where Timestamp > ago(365d)
| where LogonType == "RemoteInteractive"
```

```kql
// GOOD: justified time window
DeviceLogonEvents
| where Timestamp > ago(30d)
| where LogonType == "RemoteInteractive"
| where AccountUpn != ""
| summarize LogonCount = count() by AccountUpn, DeviceName
```

**Why it fails**: Unbounded queries are expensive, slow, and Defender caps lookback at ~30 days.

**Fix**: Always include `Timestamp > ago(Nd)` justified in the rationale.

---

## AP-Q5: The Single-Signal

**Pattern**: Single high-FP indicator without correlation.

```kql
// BAD: every scheduled task fires this
DeviceProcessEvents
| where FileName == "schtasks.exe"
```

```kql
// GOOD: multi-signal correlation
DeviceProcessEvents
| where FileName == "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine matches regex @"/tn\s+[a-zA-Z]{8}\s"
| where ProcessCommandLine has "AppData"
| join kind=inner (
    DeviceLogonEvents
    | where Timestamp > ago(30d)
    | where LogonType in ("RemoteInteractive", "NewCredentials")
) on DeviceName, $left.Timestamp == $right.Timestamp
```

**Why it fails**: No correlation = needle-in-a-haystack with no signal-to-noise separation.

**Fix**: Layer filters from the intelligence — process chain + file path + timing + network activity.

---

## AP-Q6: The Phantom Table

**Pattern**: Query references tables that don't exist in the target environment.

Common examples:
- `SecurityEvent` (legacy / Sentinel) instead of `DeviceLogonEvents` (Defender).
- `CommonSecurityLog` without verifying syslog ingestion.
- `OfficeActivity` columns referenced in `CloudAppEvents`.

**Why it fails**: Query fails silently or returns zero results — interpreted as "threat not present" rather than "query broken."

**Fix**: Confirm table availability before marking the query validated. Otherwise document required tables and mark theoretical.

---

## AP-Q7: The Invented Column

**Pattern**: Column that doesn't exist in the target table — the agent guessed or recalled it from a different table.

```kql
// BAD: AccountUpn does NOT exist in DeviceNetworkEvents
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (c2_domains)
| project Timestamp, DeviceName, AccountUpn, RemoteUrl, RemoteIP
//                                ^^^^^^^^^^ FAILS
```

```kql
// GOOD: InitiatingProcessAccountName IS documented in DeviceNetworkEvents
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (c2_domains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP
```

**Why it fails**: Defender returns `SYNTAX_ERROR: Failed to resolve scalar expression named '...'`. Wrong fixes (e.g., reducing time range) leave the query broken across all retries.

**Fix**: Never write a column name without first confirming it exists in the target table's schema reference. Different tables, different columns.

---

## AP-Q8: The Invalid Negation

**Pattern**: `!has_any` / `!contains_any` — these do not exist in KQL.

```kql
// BAD
| where InitiatingProcessFileName !has_any (browser_procs)
//                                 ^^^^^^^^^ FAILS

// GOOD
| where not(InitiatingProcessFileName has_any (browser_procs))
```

**Reference**:

| Positive | Negation | Notes |
|---|---|---|
| `has`, `contains`, `startswith`, `in`, `in~` | `!has`, `!contains`, etc. | ✅ Valid |
| `has_any`, `has_all`, `contains_any` | — | ❌ Use `not(... has_any (...))` |
| `matches regex` | — | Use `not(... matches regex ...)` |

**Why it fails**: Defender returns `Unexpected: !` at parse time.

---

## AP-Q9: The Implicit Precedence

**Pattern**: Mixes `and` and `or` without parentheses.

```kql
// BAD: "and" binds tighter than "or" — exclusion only applies to the third branch,
// but indentation suggests it applies to all.
| where FileName has_any (system_exec_tools)
    or InitiatingProcessFileName has_any (system_exec_tools)
    or ProcessIntegrityLevel == "System"
        and FileName !in~ ("svchost.exe", "services.exe", "lsass.exe")
```

```kql
// GOOD
| where FileName has_any (system_exec_tools)
    or InitiatingProcessFileName has_any (system_exec_tools)
    or (ProcessIntegrityLevel == "System"
        and FileName !in~ ("svchost.exe", "services.exe", "lsass.exe"))
```

**Why it fails**: Not a syntax error — query runs. Reviewers cannot verify intent without knowing the precedence rule; future edits introduce silent logic bugs.

**Rule**: When a `where` clause contains BOTH `and` and `or`, all `and`-groups MUST be wrapped in explicit parentheses, even when implicit precedence happens to produce the correct result.

---

## AP-Q10: The Ungrounded Aggregate

**Pattern**: Expensive `summarize` over millions of rows BEFORE selective filters.

```kql
// BAD
DeviceNetworkEvents
| where Timestamp > ago(30d)
| summarize ConnectionCount = count() by DeviceName, RemoteIP
| where ConnectionCount > 100
```

```kql
// GOOD: filter to relevant traffic first
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| where not(RemoteIP has_any (known_egress_ips))
| summarize ConnectionCount = count() by DeviceName, RemoteIP
| where ConnectionCount > 100
```

**Why it fails**: `summarize` materialises all groups before the post-aggregation `where`. On a 30-day high-volume table, this consumes huge CPU quota and may time out.

---

## AP-Q11: The Uncommented Query

**Pattern**: No inline comments explaining hunting intent, filter rationale, or intelligence connection.

**Fix**: Every query must include:
1. Header comment block (Hunt name, source, MITRE, platform, precision/recall).
2. Comments on every `let` variable (what / where from).
3. Comments on every non-obvious `where` (why it exists).
4. Comments on exclusions (why safe).

This is a **quality gate** — uncommented queries are rejected.

---

## AP-Q12: The Undocumented False Positive

**Pattern**: Query acknowledges FPs ("may return noise") but provides no triage path.

```kql
// BAD
// NOTE: this query may return many false positives from legitimate admin activity
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-encodedcommand"
```

```kql
// GOOD
// FP expectation: software-deployment tooling uses -EncodedCommand for software push.
// Triage: check InitiatingProcessFileName — deployment tooling typically runs as ccmexec.exe
//   or similar service host. If parent is the deployment service AND AccountName is SYSTEM,
//   likely benign. Exclude.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-encodedcommand"
| where InitiatingProcessFileName !in~ ("ccmexec.exe", "svchost.exe")
```

**Fix**: Every query's FP scenarios must include specific actionable triage steps. Vague phrases ("investigate further") are rejected.

---

## AP-Q13: The Short-Term Filter

**Pattern**: `has` with terms ≤ 3 chars (not indexed).

```kql
// BAD: "cmd" is 3 chars — full column scan
| where ProcessCommandLine has "cmd"

// GOOD
| where FileName in~ ("cmd.exe")
| where ProcessCommandLine has "net.exe" or ProcessCommandLine has "net1.exe"
```

**Fix**: Avoid `has` with terms ≤ 3 chars. Use `FileName` exact match for short binary names, or combine with longer indexed terms.

---

## AP-Q14: The Calculated Column Filter

**Pattern**: `extend`-computed column then filter on it.

```kql
// BAD
| extend CmdLower = tolower(ProcessCommandLine)
| where CmdLower contains "invoke-mimikatz"

// GOOD: case-insensitive operator on raw column
| where ProcessCommandLine has "Invoke-Mimikatz"
```

**Why it fails**: `extend` materialises a new column for every row; case-insensitive operators (`has`, `contains`, `in~`) make `tolower()` unnecessary.

---

## AP-Q15: The Assumed Causality

**Pattern**: Multi-table join without time-window validation; PIDs are recycled.

```kql
// BAD: matches January process with February network event
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "powershell.exe"
| join kind=inner (
    DeviceNetworkEvents | where Timestamp > ago(30d)
) on DeviceId, $left.ProcessId == $right.InitiatingProcessId
```

```kql
// GOOD: validate temporal proximity
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "powershell.exe"
| project ProcessTime = Timestamp, DeviceId, ProcessId, DeviceName, ProcessCommandLine
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | project NetworkTime = Timestamp, DeviceId, InitiatingProcessId, RemoteUrl, RemoteIP
) on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| where (NetworkTime - ProcessTime) between (0min .. 5min)
```

**Fix**: Add `where (eventB_time - eventA_time) between (0min .. Nmin)` after multi-table joins. Use `ProcessUniqueId` / `InitiatingProcessUniqueId` instead of PIDs where available.

---

## AP-Q16: The Enrichment Assumption

**Pattern**: `invoke FileProfile()` without handling missing data.

```kql
// BAD
DeviceProcessEvents
| where Timestamp > ago(7d)
| invoke FileProfile(SHA256, 1000)
| where GlobalPrevalence <= 250

// GOOD
DeviceProcessEvents
| where Timestamp > ago(7d)
| invoke FileProfile(SHA256, 1000)
| where GlobalPrevalence <= 250 or isempty(GlobalPrevalence)
```

**Why it fails**: `FileProfile()` enrichment depends on Microsoft backend telemetry. New files, internal-only binaries, isolated-network binaries have no prevalence — silently dropped.

**Fix**: Always include `or isempty(GlobalPrevalence)` (or equivalent null check). Document the enrichment dependency in the query rationale.

---

## Quick reference

| Red flag | Anti-pattern | Action |
|---|---|---|
| Expected results > 1000 in clean env | AP-Q1 (Dragnet) | Add filters from intel |
| No inline KQL comments | AP-Q3 / AP-Q11 | Add comments + rationale |
| No `Timestamp` filter | AP-Q4 (Time Bomb) | Add justified bound |
| Single `where` on high-volume field | AP-Q5 (Single-Signal) | Add correlation |
| `AccountUpn` in DeviceNetworkEvents/DeviceEvents | AP-Q7 (Invented Column) | Look up correct column |
| `!has_any` / `!contains_any` | AP-Q8 (Invalid Negation) | Use `not(... has_any (...))` |
| `and` + `or` without parentheses | AP-Q9 (Implicit Precedence) | Parenthesise all `and` groups |
| `summarize` before selective `where` | AP-Q10 (Ungrounded Aggregate) | Filter aggressively first |
| "May return FPs" with no triage | AP-Q12 (Undocumented FP) | Add specific triage steps |
| `has` with term ≤ 3 chars | AP-Q13 (Short-Term Filter) | Use exact match or longer qualifiers |
| Filter on `extend`-computed column | AP-Q14 (Calculated Column Filter) | Filter raw column |
| Multi-table join without time window | AP-Q15 (Assumed Causality) | Add `between (0min .. Nmin)` |
| `FileProfile()` without null handling | AP-Q16 (Enrichment Assumption) | Add `or isempty(GlobalPrevalence)` |
