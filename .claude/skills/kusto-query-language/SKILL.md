---
name: kusto-query-language
description: Platform-agnostic Kusto Query Language (KQL) patterns, optimisation rules, anti-patterns, and correlation techniques shared by Microsoft Sentinel and Microsoft Defender Advanced Hunting. Covers operator hierarchy, filter ordering, joins, summarise patterns, commenting discipline, false-positive engineering, IOC templates, and bug-class anti-patterns. Use when authoring or reviewing any KQL — pair with microsoft-sentinel or microsoft-defender-endpoint for table schemas, ingestion semantics, and platform-native rule constraints.
---

# Kusto Query Language — platform-agnostic

This skill encodes the language-level discipline shared across Microsoft Sentinel (Log Analytics) and Microsoft Defender Advanced Hunting (M365 Defender). For platform-specific table schemas, time-field names, NRT/scheduled-rule constraints, retention and execution surfaces, **always pair with `microsoft-sentinel` or `microsoft-defender-endpoint`**.

> Note on time-field naming: Sentinel tables use `TimeGenerated`. Defender device/email tables use `Timestamp`. The optimisation principles in this skill are identical — always filter on the datetime index first.

---

## 1. Operator hierarchy and string operations

### 1.1 Filter cascade — most efficient first

| Priority | Filter type | Mechanism | Example |
|---|---|---|---|
| 1 | Time field | Datetime index → shard elimination | `TimeGenerated > ago(7d)` / `Timestamp > ago(7d)` |
| 2 | `has_cs` / `has` | Term-level inverted index lookup | `ProcessCommandLine has "mimikatz"` |
| 3 | `==` / `in` / `in~` | Exact match against indexed values | `ActionType == "ProcessCreated"` |
| 4 | Numeric / boolean | Column scan, fast | `RemotePort == 443` |
| 5 | `contains` family | Full column scan | `RemoteUrl contains "xploi"` |
| 6 | `matches regex` | Full scan + regex engine | `... matches regex @"..."` |

```kql
// GOOD: time first, then narrow enums, then term lookup, regex last
SourceTable
| where TimeGenerated > ago(7d)
| where ActionType == "ProcessCreated"
| where FileName has "powershell"
| where ProcessCommandLine has "-enc"
| where ProcessCommandLine matches regex @"(?i)-e(nc|ncodedcommand)\s+[A-Za-z0-9+/]"
```

### 1.2 String operator selection

| Operator | Indexed | Speed | Use when |
|---|---|---|---|
| `has_cs` | yes (case-sensitive) | fastest | Token, casing known |
| `has` | yes | fast | Token, casing variable |
| `has_any` / `has_all` | yes | fast | Multi-token membership / conjunction |
| `==` / `in` / `in~` | yes | fast | Exact / set membership |
| `startswith_cs` / `startswith` | partial | medium | Known prefix |
| `contains_cs` / `contains` | no | slow | Substring within tokens |
| `matches regex` | no | slowest | True pattern matching |

**Decision tree**:
1. Complete token? → `has` / `has_cs`.
2. One of several tokens? → `has_any`.
3. Exact value? → `==` / `in`.
4. Substring within a token? → `contains` (and document why `has` is insufficient).
5. Pattern? → `matches regex`, last resort.

### 1.3 Case-sensitive when possible

Case-sensitive operators skip Unicode normalisation. Prefer `==`, `in`, `has_cs`, `contains_cs`, `startswith_cs` when the data has consistent casing. Use case-insensitive variants for fields with known casing drift (Windows file names, UPNs, UNC paths).

### 1.4 Short-term limitation

Terms ≤ 3 characters are not held in the term index. `has "cmd"` triggers a full column scan. Use `FileName in~ ("cmd.exe")` or combine with longer indexed terms.

### 1.5 Negation traps

Single-value operators support `!`. Multi-value operators do **not**.

| Positive | Valid negation |
|---|---|
| `has`, `contains`, `startswith`, `in`, `in~` | `!has`, `!contains`, etc. ✅ |
| `has_any`, `has_all`, `contains_any` | ❌ — wrap with `not(... has_any (...))` |
| `matches regex` | `not(... matches regex ...)` |

```kql
// BAD: !has_any is invalid syntax
| where Column !has_any (value_list)
// GOOD
| where not(Column has_any (value_list))
```

### 1.6 Boolean precedence — explicit parentheses required

`and` binds tighter than `or` (same as most languages). When a `where` clause mixes both, **all `and`-groups must be wrapped in explicit parentheses** even when implicit precedence happens to produce the correct result. Future edits will silently break otherwise.

```kql
// BAD
| where FileName has_any (tools)
    or ProcessIntegrityLevel == "System"
        and FileName !in~ ("svchost.exe", "services.exe")
// GOOD
| where FileName has_any (tools)
    or (ProcessIntegrityLevel == "System"
        and FileName !in~ ("svchost.exe", "services.exe"))
```

---

## 2. Time, joins, aggregations

### 2.1 Time bounds

Always first; always justified in the rationale. Production scheduled rules manage their own lookback — see platform skills for when to **omit** `TimeGenerated`/`Timestamp` filters (NRT pipelines, MDE custom detections).

### 2.2 Joins

- **Smaller, more-filtered side on the left.** Joins look up each left row in the right table.
- **Time-bound both sides.** Reduces inner-table scan even when seemingly redundant.
- **Pick the right `kind`**: `innerunique` (default) deduplicates left rows; use `inner` when all matches are needed; `leftouter` for enrichment; `leftanti` for exclusion-based hunting / baseline deviation; `leftsemi` for existence checks.
- **Hints**: `hint.shufflekey = <key>` for high-cardinality keys; `hint.strategy = broadcast` when left side is small (< 100k) and right is very large.

```kql
TableA
| where TimeGenerated > ago(7d)
| where /* selective filters */
| project SmallProjection
| join kind=inner (
    TableB
    | where TimeGenerated > ago(7d)
    | where /* selective filters */
) on JoinKey
```

### 2.3 Temporal-window joins

Multi-table correlation must validate temporal causality. Process IDs are recycled on Windows; without a time window a January process can match a February network event sharing the same DeviceId+ProcessId.

```kql
// Pattern: B happens within N minutes of A
let event_a =
    TableA
    | where TimeGenerated > ago(7d)
    | project TimeA = TimeGenerated, JoinKey, ContextA;
let event_b =
    TableB
    | where TimeGenerated > ago(7d)
    | project TimeB = TimeGenerated, JoinKey, ContextB;
event_a
| join kind=inner event_b on JoinKey
| where (TimeB - TimeA) between (0min .. 30min)
```

Where available, join on stable identifiers (`ProcessUniqueId` / `InitiatingProcessUniqueId`) rather than recycled PIDs.

### 2.4 Aggregations

- **`project`, not `summarize by`** when the column is already unique per row.
- **Aggregate after selective filters**, never before — `summarize` materialises every group before the post-aggregation `where`.
- **`hint.shufflekey`** when grouping by columns with millions of distinct values.
- Reduce columns before `join`/`summarize` to lower memory pressure.

### 2.5 Filter raw columns, not calculated ones

```kql
// BAD: extend creates a column for every row, then scans it
| extend CmdLower = tolower(ProcessCommandLine)
| where CmdLower contains "invoke-mimikatz"
// GOOD
| where ProcessCommandLine has "Invoke-Mimikatz"
```

`has`, `contains`, `in~` are already case-insensitive — `tolower()` is unnecessary and slow.

---

## 3. Mandatory comment discipline

Every query opens with a structured header:

```kql
// ============================================================
// Hunt: <hypothesis name>
// Purpose: <one-line description>
// Source intelligence: <reference / TLP-respecting pointer>
// MITRE ATT&CK: <technique id - name>
// Platform: <SENTINEL | DEFENDER | both>
// Precision: <HIGH/MEDIUM/LOW> | Recall risk: <HIGH/MEDIUM/LOW>
// ============================================================
```

**Comment rules**:
- Every `let` variable: what value, where it came from.
- Every non-trivial `where`: **why** it exists.
- Every exclusion: why it is safe.
- Every `summarize` / `join`: what is being correlated and why.

| Bad (reject) | Good (accept) |
|---|---|
| `// Filter by filename` | `// mshta.exe → PowerShell chain documented as first-stage loader in source` |
| `// Check network events` | `// Outbound 8443: source intel documents non-standard C2 port` |
| `// Remove false positives` | `// Exclude corporate egress IPs: legitimate proxy traffic` |

Detection rules without inline rationale fail review.

---

## 4. `let`, IOCs, reusable references

```kql
// Tuning thresholds with guidance
let threshold_failures = 50;  // Default 50 — lower for privileged accounts, raise for service accounts
let lookback = ago(14d);

// IOC arrays with provenance comments
let malicious_ips = dynamic(["203.0.113.10", "198.51.100.20"]);  // Source: <reference>
let malicious_domains = dynamic(["evil.example", "c2.example.net"]);
```

- **Inline IOCs** with `let` + `dynamic([...])`; avoid `externaldata()` for production rules unless your tenant explicitly supports it.
- **Inline reference tables** via `datatable(...)` for known-good lists, Tier 0 groups, exclusion lookups.
- **`materialize()`** when the same intermediate set feeds multiple downstream joins (e.g. TI feed dedup before joining against multiple log tables).

```kql
let active_ti = materialize(
    TIIndicators
    | where TimeGenerated > ago(14d)
    | where ExpirationDateTime > now() and Active == true
    | summarize arg_max(TimeGenerated, *) by IndicatorId
    | extend TI_IP = coalesce(NetworkIP, NetworkSourceIP, NetworkDestinationIP)
    | where isnotempty(TI_IP)
    | project TI_IP, ThreatType, ConfidenceScore
);
// Reuse active_ti against multiple log tables …
```

---

## 5. Advanced operators worth knowing

| Operator | Purpose | Use case |
|---|---|---|
| `materialize()` | Cache intermediate result | Reused subqueries, TI dedup |
| `mv-apply` | Per-element array operations | Beaconing intervals, array conditions |
| `set_difference()` | Historical baseline comparison | New autoruns, new scheduled tasks |
| `datatable()` | Inline reference table | Known-good lists, Tier 0 groups |
| `prev()` / `next()` | Window functions | Impossible travel, sequential analysis |
| `row_window_session()` | Dynamic session windows | Brute-force clustering (better than fixed `bin()`) |
| `series_decompose_anomalies()` | ML anomaly detection | Volume spikes; pair with `make-series` |
| `series_outliers()` | Statistical outlier removal | Cleaning baselines |
| `arg_max()` / `arg_min()` | Row with extreme value per group | Latest event per entity, indicator dedup |
| `top-nested N of X by Y` | Nested rarity / prevalence | Rare processes per device, rare apps per user |
| `coalesce()` | First non-null across columns | TI IP normalisation |
| `parse kind=regex flags=iU` | Case-insensitive ungreedy regex | Command-line / URL extraction |
| `ipv4_is_in_range()` | CIDR matching | Subnet filtering without strings |

### `make-series` + anomaly detection

```kql
SourceTable
| where TimeGenerated > ago(30d)
| make-series Count = count() on TimeGenerated from ago(30d) to now() step 1h by Entity
| extend (Anomalies, Score, Expected) = series_decompose_anomalies(Count, 1.5)
| mv-apply Anomalies on (where Anomalies == 1 | take 1)
| project Entity, Count, Expected, Score
```

---

## 6. False-positive engineering

Production-shaped queries surface tuning knobs explicitly:

```kql
// Tuning thresholds — adjust per environment
let threshold_count = 50;
let threshold_unique = 10;
let lookback = ago(7d);

SourceTable
| where TimeGenerated > lookback
| where /* core hunt logic */
// --- BEGIN ENVIRONMENT FILTERS (customise per deployment) ---
| where AccountName !in~ ("svc_monitoring", "svc_backup")
| where DeviceName !startswith "SCAN-"
// --- END ENVIRONMENT FILTERS ---
```

**Alert deduplication** via `leftanti` against existing alerts/incidents (adapt table/column names per platform):

```kql
// Pattern: exclude entities already in recent alerts
| join kind=leftanti (
    AlertTable                              // Platform-specific alert table
    | where TimeField > ago(7d)
    | where Status != "Dismissed"
    | extend AlertEntity = tostring(parse_json(Entities)[0].EntityIdentifier)
    | project AlertEntity
) on $left.EntityColumn == $right.AlertEntity
```

---

## 7. IOC query templates

The blocks below are detection-query examples. They are not commands this skill runs. Download and invoke names in the last pipeline are indicator strings to match in a decoded command line.

Replace platform-specific table/column names per the relevant platform skill.

```kql
// IP address lookup
let malicious_ips = dynamic(["IP1", "IP2"]);
NetworkTable
| where TimeGenerated > ago(30d)
| where DestinationIP in (malicious_ips) or SourceIP in (malicious_ips)
| project TimeGenerated, SourceIP, DestinationIP, /* enrichment */

// Domain lookup
let malicious_domains = dynamic(["domain1.example", "domain2.example"]);
DnsTable
| where TimeGenerated > ago(30d)
| where DomainColumn has_any (malicious_domains)

// Hash lookup
let malicious_hashes = dynamic(["sha256_1", "sha256_2"]);
FileTable
| where TimeGenerated > ago(30d)
| where SHA256 in (malicious_hashes)

// Base64-encoded payload pipeline — detection example, not a command to run
// NOTE: Replace table/column names per platform skill (Defender: DeviceProcessEvents/Timestamp; Sentinel: SecurityEvent or Event/TimeGenerated)
ProcessTable
| where TimeField > ago(14d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-encodedcommand", "-e ")
| parse ProcessCommandLine with * "-enc" * " " EncodedBlock:string
| extend DecodedCommand = base64_decode_tostring(EncodedBlock)
| where isnotempty(DecodedCommand)
| where DecodedCommand has_any ("Invoke-WebRequest", "DownloadString", "IEX")
| project TimeField, DeviceName, AccountName, DecodedCommand, ProcessCommandLine
```

---

## 8. Rationale & scoring fields (when feeding hunting/MDR records)

When KQL is embedded in a record that carries a `rationale` field (hunt query objects, opentide MDR `description`/`response.procedure`), the rationale must answer four questions:

1. **Why these tables?** What captures the observable; what was rejected.
2. **Why these filters?** Map every non-trivial filter to source intelligence or behavioural reasoning.
3. **What the query does NOT cover.** Variants, evasion, scenarios excluded by scope.
4. **How the result connects to the hypothesis.** What a true positive would prove.

| Score | Precision (FP volume in clean env) | Recall risk |
|---|---|---|
| HIGH | < 10 results; filters trace to specific intel | Filters are narrow; variants may evade |
| MEDIUM | 10–100; mix of specific + behavioural | Covers known patterns; novel variants may evade |
| LOW | > 100; broad behavioural pattern | Broad detection; hard to evade |

---

## 9. Quality checklist

- [ ] Time bound present as **first** filter (or omitted intentionally for NRT, with rationale).
- [ ] No full-table scans (at least one selective predicate beyond time).
- [ ] `has`/`has_any` over `contains` wherever applicable.
- [ ] Output reduced via `project` or `summarize` — never return all columns.
- [ ] Inline comments per non-trivial filter, exclusion, join, summarise.
- [ ] Header block (Hunt, Purpose, Source, MITRE, Platform, Precision/Recall) populated.
- [ ] No multi-value `!has_any` / `!has_all` / `!contains_any` (use `not(...)`).
- [ ] `and`/`or` mixes parenthesised explicitly.
- [ ] No `has` with terms ≤ 3 chars.
- [ ] Calculated-column filters replaced with raw-column filters where possible.
- [ ] Multi-table joins time-windowed via `between`.
- [ ] Enrichment functions (`FileProfile`, etc.) handle `isempty()`/null cases.
- [ ] `let` thresholds carry tuning comments.
- [ ] FP scenarios documented with **actionable triage steps**, not vague phrases.

---

## 10. Reference catalogues

- `references/Best-Practices.md` — Full optimisation, operator, and FP engineering reference.
- `references/Hypothesis-Anti-Patterns.md` — AP-H1…AP-H5 hypothesis rejection checklist.

For platform-specific anti-patterns, table schemas, and execution surfaces:
- `microsoft-sentinel/references/Anti-Patterns.md`
- `microsoft-defender-endpoint/references/Anti-Patterns.md`
