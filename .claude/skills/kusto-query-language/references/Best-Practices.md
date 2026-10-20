# KQL Best Practices — platform-agnostic

Authoritative performance and correctness guidelines for KQL queries across Microsoft security platforms (Defender Advanced Hunting, Microsoft Sentinel). Only platform-neutral rules are included here. For platform-specific constraints (rate limits, max rows, timeouts, retention, table schemas), see the `microsoft-sentinel` and `microsoft-defender-endpoint` skills.

> **Sources**: Adapted from [Kusto query best practices](https://learn.microsoft.com/en-us/azure/kusto/query/best-practices) and [Advanced hunting query best practices](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-best-practices).

---

## String operations

### Token-based vs substring search

KQL maintains an inverted **term index** on string columns. Operators that leverage this index are dramatically faster than those requiring full column scans.

| Operator | Mechanism | Speed | Use when |
|---|---|---|---|
| `has_cs` | Case-sensitive term index | Fastest | Exact case-sensitive token |
| `has` | Term index | Fast | Token, casing variable |
| `has_any` | Multi-term index | Fast | Any of several tokens |
| `has_all` | Multi-term index | Fast | All of several tokens |
| `==` / `in` | Exact match | Fast | Complete value known |
| `startswith_cs` / `startswith` | Prefix scan | Medium | Known prefix |
| `contains_cs` / `contains` | Full column scan | Slow | Substring within tokens |
| `matches regex` | Full scan + regex | Slowest | Pattern matching |

**Decision tree**:
1. Complete word/token? → `has` / `has_cs`
2. One of several tokens? → `has_any`
3. Exact known string? → `==` / `in`
4. Substring within a token? → `contains` (document why `has` won't work)
5. Pattern? → `matches regex` (last resort)

### Case sensitivity

Case-sensitive operators skip Unicode normalisation:

| Prefer | Over | When |
|---|---|---|
| `==` | `=~` | Casing known |
| `in` | `in~` | Set with known casing |
| `has_cs` | `has` | Token search, casing known |
| `contains_cs` | `contains` | Substring, casing known |
| `startswith_cs` | `startswith` | Prefix, casing known |

**Use the case-insensitive variant for**: Windows file names, UPNs, UNC paths, anything where source systems produce inconsistent casing.

### Short-term limitation

Terms ≤ 3 characters are not indexed. `has "cmd"` falls back to a full column scan. Match the executable name (`FileName in~ ("cmd.exe")`) or combine with longer indexed terms.

### Negation operators

Single-value operators support `!`. Multi-value operators do **not**:

| Positive | Valid? |
|---|---|
| `!has`, `!contains`, `!startswith`, `!in`, `!in~` | ✅ |
| `!has_any`, `!has_all`, `!contains_any` | ❌ — wrap in `not(...)` |
| `not(... matches regex ...)` | ✅ |

```kql
// BAD: !has_any is not valid
| where Column !has_any (value_list)
// GOOD
| where not(Column has_any (value_list))
```

---

## Time operations

### Time field filtering

Time is the most selective filter — it eliminates entire shards before any further processing. **Always place time filters first.**

```kql
// GOOD
TableName
| where TimeField > ago(7d)
| where OtherFilter == "value"

// BAD
TableName
| where OtherFilter == "value"
| where TimeField > ago(7d)
```

> Time-field naming differs by platform: Sentinel uses `TimeGenerated`; Defender device/email tables use `Timestamp`. The optimisation principle is identical.

### Lookback justification

Every `ago(Nd)` must be justified in the query rationale:
- Campaign window (campaign active since specific date) → match window
- Incident response → 7–14 days
- Real-time monitoring → 1 day

---

## Join optimisation

### Smaller table on the left

Joins look up each left row in the right table. Fewer left rows = fewer lookups.

```kql
// GOOD: filtered, smaller table on left
SmallFilteredTable
| join kind=inner (LargerTable | where TimeField > ago(7d)) on JoinKey

// BAD
LargerTable
| join (SmallFilteredTable) on JoinKey
```

### Time-bound both sides

Always add time filters to both sides, even if redundant. Reduces inner-table scan.

### Join kinds

| Kind | Behaviour | Use when |
|---|---|---|
| `innerunique` (default) | Deduplicates left rows | Standard correlation |
| `inner` | All matching pairs | Need every match |
| `leftouter` | All left + matching right | Enrichment |
| `leftanti` | Left rows with NO right match | Exclusion-based hunting, baseline deviation |
| `leftsemi` | Left rows with ANY right match | Existence check without right columns |

### Join hints

| Hint | Use when |
|---|---|
| `hint.shufflekey = <key>` | High-cardinality key (millions of distinct values) |
| `hint.strategy = broadcast` | Left < ~100k rows, right very large |

### Pre-aggregate before join

```kql
TableA
| where TimeField > ago(7d)
| summarize Events = count(), Items = make_set(Col) by JoinKey
| join (TableB | where TimeField > ago(7d)) on JoinKey
```

---

## Aggregation

### `summarize` vs `project`

If a column is unique per row, `project` is sufficient and avoids aggregation overhead.

### Shuffle for high-cardinality aggregation

```kql
| summarize hint.shufflekey = HighCardinalityColumn count(), dcount(OtherColumn)
    by HighCardinalityColumn, GroupColumn
```

---

## `let` bindings

### Thresholds with tuning guidance

```kql
let threshold = 50;          // Default 50 — lower for sensitive segments, raise for noisy networks
let lookback = ago(14d);
```

### IOC lists with provenance

```kql
let target_ips = dynamic(["203.0.113.10", "198.51.100.20"]);  // Source: <reference>
```

### `dynamic()` for IOCs

Always use `let` + `dynamic()`. Never inline IOCs directly in `where`.

### `datatable()` for reference tables

Use for known-good lists, Tier 0 groups, exclusion lists:

```kql
let known_good = datatable(Name: string) [
    "SecurityHealth", "Windows Defender", "OneDrive", "Teams"
];
```

> **`externaldata()`**: works for some tenants, but many production environments execute KQL from runners without external network access (CI, agent-driven hunts). Prefer `datatable()` for reproducibility.

---

## Projection

### Project early, project often

1. Before `join` — project only the join key plus needed columns on both sides.
2. After `join` — `project-away` to remove duplicate join-key columns.
3. Before `summarize` — keep only what is needed for aggregation/grouping.

```kql
TableA
| where TimeField > ago(7d)
| project TimeField, JoinKey, NeededA
| join kind=inner (
    TableB
    | where TimeField > ago(7d)
    | project TimeField, JoinKey, NeededB
) on JoinKey
| project-away JoinKey1
```

### Never return all columns

Every query MUST end with explicit `project` or `summarize`.

---

## Performance anti-patterns

### AP-P1: Regex before filter

```kql
// BAD: regex over entire table
| where ProcessCommandLine matches regex @"(?i)invoke-(web|rest)request"

// GOOD: pre-filter with indexed term, then regex for precision
// Indicator strings in a detection example, not commands to run
| where ProcessCommandLine has_any ("Invoke-WebRequest", "Invoke-RestMethod")
| where ProcessCommandLine matches regex @"(?i)invoke-(web|rest)request"
```

### AP-P2: Calculated column filter

```kql
// BAD
| extend Domain = tostring(parse_url(Url).Host)
| where Domain has "evil.example"

// GOOD
| where Url has "evil.example"
| extend Domain = tostring(parse_url(Url).Host)
```

### AP-P3: Unnecessary summarise

```kql
// BAD
| summarize by UniqueColumn, OtherColumn
// GOOD
| project UniqueColumn, OtherColumn
```

### AP-P4: Unfiltered join side

```kql
// BAD
| join kind=inner (OtherTable) on Key
// GOOD
| join kind=inner (OtherTable | where TimeField > ago(7d)) on Key
```

### AP-P5: `contains` where `has` suffices

```kql
// BAD
| where Column contains "mimikatz"
// GOOD
| where Column has "mimikatz"
```

---

## Command-line query patterns

Adversaries obfuscate command lines. Build durable queries:

### Don't match exact command strings

```kql
// BAD: brittle
| where ProcessCommandLine == "net stop MpsSvc"

// BETTER: match process name + key arguments independently
| where FileName in~ ("net.exe", "net1.exe")
| where ProcessCommandLine has "stop"
| where ProcessCommandLine has "MpsSvc"

// BEST: also handle quote obfuscation
| where FileName in~ ("net.exe", "net1.exe")
| extend CleanCmd = replace_string(ProcessCommandLine, "\"", "")
| where CleanCmd has "stop" and CleanCmd has "MpsSvc"
```

### Match `FileName`, not path

```kql
// GOOD
| where FileName in~ ("net.exe", "net1.exe")
// BAD: path-dependent
| where ProcessCommandLine startswith "C:\\Windows\\System32\\net.exe"
```

### `parse_command_line()` for argument extraction

```kql
| extend ParsedArgs = parse_command_line(ProcessCommandLine, "windows")
| where ParsedArgs has "-ExecutionPolicy"
```

---

## False-positive engineering

### Prevalence-based filtering

```kql
// MDE: FileProfile for global prevalence
| invoke FileProfile(SHA1, 1000)
| where GlobalPrevalence < 200 or isempty(GlobalPrevalence)  // include enrichment gaps

// Local prevalence via dcount
| summarize DeviceCount = dcount(DeviceName) by FileName, SHA256
| where DeviceCount <= 3
```

### Trusted entity exclusion

```kql
// Certificate trust check (Defender)
| join kind=leftouter DeviceFileCertificateInfo on SHA1
| where not(IsTrusted == 1 and IsRootSignerMicrosoft == 1)

// Known-good list via datatable
let known_good = datatable(ProcessName: string) [
    "SecurityHealthService.exe", "MsMpEng.exe", "OneDrive.exe"
];
| where not(FileName in~ (known_good))

// Machine account exclusion (NTLM relay detection)
| where not(AccountName endswith "$")
```

### Inline analyst-tunable exclusion

```kql
let excluded_devices = datatable(DeviceName: string) [
    "KIOSK-01", "LAB-SANDBOX-03"
];
let excluded_processes = datatable(ProcessName: string) [
    "monitoring-agent.exe", "backup-service.exe"
];
DeviceProcessEvents
| where not(DeviceName in (excluded_devices))
| where not(FileName in~ (excluded_processes))
```

### Private IP filtering

```kql
| where not(ipv4_is_private(RemoteIP))
```

### Outlier-based cleaning (beaconing)

```kql
| extend OutlierFlags = series_outliers(IntervalSeries)
| mv-apply Interval = IntervalSeries, Flag = OutlierFlags on (
    where Flag between (-1.5 .. 1.5)
)
| extend CleanJitter = (stdev(CleanIntervals) / avg(CleanIntervals)) * 100
```

### Path normalisation for historical comparison

```kql
| extend NormalizedPath = replace_regex(FolderPath, @"C:\\Users\\[^\\]+", @"C:\Users\userxx")
| extend NormalizedPath = replace_regex(NormalizedPath, @"\{[0-9a-fA-F-]+\}", @"{xxxxxxxxxx}")
| extend NormalizedPath = replace_regex(NormalizedPath, @"\d+\.\d+\.\d+\.\d+", @"X.Y.Z.T")
```

---

## Advanced performance techniques

### `materialize()` for multi-use results

```kql
// BAD: stage1 computed twice
let stage1 = ExpensiveQuery | where [filters];
let a = stage1 | join (T2) on K;
let b = stage1 | join (T3) on K;

// GOOD
let stage1 = materialize(ExpensiveQuery | where [filters]);
let a = stage1 | join (T2) on K;
let b = stage1 | join (T3) on K;
```

### `toscalar()` for static lookups

```kql
let target_devices = toscalar(
    DeviceInfo
    | where IsInternetFacing == 1
    | summarize make_set(DeviceId)
);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceId in (target_devices)
```

### `hint.strategy=shuffle` for large datasets

```kql
TableA | join hint.strategy=shuffle (TableB) on HighCardinalityKey
| summarize hint.shufflekey=DeviceId count() by DeviceId, ProcessName
```

Don't use on small datasets — shuffle overhead exceeds the benefit.

### Pre-filter before expensive parsing

```kql
// GOOD: cheap filters first
Event
| where RenderedDescription has_any ("http://", "https://")
| where RenderedDescription has_any ("msedge.exe", "chrome.exe")
| extend EventData = parse_xml(EventData)
```

### `arg_max()` for deduplication

```kql
| summarize arg_max(Timestamp, *) by DeviceName
```

---

## Operator reference (community-sourced)

### `find` / `search` — cross-table IOC sweep

```kql
find in (DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents, DeviceRegistryEvents)
where SHA256 == "abc123..." or FileName has "malware"
| project $table, Timestamp, DeviceId, FileName

search in (DeviceProcessEvents, DeviceFileEvents, DeviceRegistryEvents)
Timestamp > ago(7d) and "mimikatz"
```

### `top-nested` — hierarchical top-N

```kql
DeviceProcessEvents
| top-nested 5 of DeviceName by device_count = count(),
  top-nested 3 of FileName by process_count = count()
```

### `column_ifexists()` — schema-safe access

```kql
| extend FileOrigin = column_ifexists("FileOriginUrl", "")
| where isnotempty(FileOrigin)
```

### `sequence_detect()` — ordered event chain matching

```kql
CommonSecurityLog
| project TimeGenerated, RequestURL, SourceIP
| evaluate sequence_detect(
    TimeGenerated, 5s, 8s,
    login=(RequestURL has "login.microsoftonline.com"),
    graph=(RequestURL has "graph.microsoft.com/v1.0/me/drive/"),
    SourceIP)
```

### `basket()` / `autocluster()` — unsupervised pattern mining

```kql
SigninLogs
| where ResultType != 0
| project UserPrincipalName, IPAddress, AppDisplayName, Location
| evaluate basket(0.05)
```

### `lookup` — lightweight broadcast join

```kql
LargeTable
| lookup kind=leftouter SmallReferenceTable on JoinKey
```

Smaller right side broadcasts; faster than `join` when one side is small.
