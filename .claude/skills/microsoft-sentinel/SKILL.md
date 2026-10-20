---
name: microsoft-sentinel
description: Microsoft Sentinel (Azure Log Analytics) hunting, analytic-rule, and detection authoring guidance — table-domain decision matrix, identity/cloud workload schemas (SigninLogs, AuditLogs, AzureActivity, OfficeActivity, CommonSecurityLog), TimeGenerated discipline, ResultType code patterns, NRT vs scheduled rule constraints, watchlists, ASIM caveats, materialise+arg_max+coalesce TI patterns, row_window_session sessionisation, BehaviorAnalytics/IdentityInfo enrichment. Always pair with kusto-query-language for language-level optimisation. Use for configurations.sentinel blocks in opentide MDR objects and Sentinel-first hypotheses.
---

# Microsoft Sentinel — hunting & detection

Author and review KQL for Microsoft Sentinel (Azure Log Analytics) workspaces. This skill covers Sentinel-native tables and operational specifics; for endpoint telemetry (process, file, registry, device-level network) use **`microsoft-defender-endpoint`**; for vendor-neutral KQL optimisation use **`kusto-query-language`**.

---

## 1. When to use Sentinel vs Defender

| Telemetry domain | Platform | Primary tables |
|---|---|---|
| Identity & authentication | **Sentinel** | `SigninLogs`, `AuditLogs`, `AADNonInteractiveUserSignInLogs` |
| Azure resource operations | **Sentinel** | `AzureActivity`, `AzureDiagnostics` |
| Office 365 / SaaS | **Sentinel** | `OfficeActivity`, `CloudAppEvents` |
| Network appliances (firewall, proxy) | **Sentinel** | `CommonSecurityLog`, `Syslog` |
| Windows Security Events (non-Defender) | **Sentinel** | `SecurityEvent`, `WindowsEvent` |
| DNS queries | **Sentinel** | `DnsEvents`, `DnsInventory` |
| Threat intelligence matching | **Sentinel** | `ThreatIntelligenceIndicator` (newer tenants may use `ThreatIntelIndicators`) |
| UEBA anomalies | **Sentinel** | `BehaviorAnalytics` |
| Identity enrichment | **Sentinel** | `IdentityInfo` |
| Watchlists | **Sentinel** | `_GetWatchlist('name')` |
| Workspace audit | **Sentinel** | `SentinelAudit`, `SentinelHealth` |
| Endpoint processes/files/registry | **Defender** | `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceRegistryEvents` |
| Device-level network | **Defender** | `DeviceNetworkEvents`, `DeviceNetworkInfo` |
| Email | **Defender** | `EmailEvents`, `EmailUrlInfo` |

**Rule**: If the hypothesis targets identity, cloud infrastructure, SaaS, or cross-platform correlation, use Sentinel. If it targets endpoint behaviour (process execution, file ops, device-level network), use Defender.

**Cross-platform hypotheses** (e.g., credential phishing → endpoint execution): generate **separate queries per platform** with the correct platform tag. Cross-table joins between Sentinel and Defender are unreliable; correlate at the analyst/playbook layer.

---

## 2. Column authority — non-negotiable

> The tenant-specific table schema reference (typically `references/Sentinel-Tables.md` in your content repo) is the **only** source of truth for Sentinel table columns. Do not invent, guess, or recall column names from memory — always look them up in the live schema document.

**Procedure**: Before writing any column name:
1. Open the tenant's table reference.
2. Find the target table and confirm the column appears in its key columns.

### Critical Sentinel ↔ Defender column differences

Wrong column = guaranteed `SYNTAX_ERROR`. Common contamination traps:

| Concept | Sentinel column | Defender column | Notes |
|---|---|---|---|
| Timestamp | `TimeGenerated` | `Timestamp` | All Sentinel tables use `TimeGenerated` |
| Device identifier | `Computer` (hostname) | `DeviceId` (UUID) | `SecurityEvent` uses `Computer` |
| User account | `TargetUserName` / `SubjectUserName` | `AccountName` | `SecurityEvent` |
| User principal | `UserPrincipalName` | `AccountUpn` | `SigninLogs` |
| Process command line | `CommandLine` | `ProcessCommandLine` | `SecurityEvent` (4688) |
| Source IP | `IpAddress` / `CallerIpAddress` | `RemoteIP` | `SigninLogs`, `AzureActivity` |

**Do not copy Defender column names into Sentinel queries** or vice versa.

### Sentinel-specific schema considerations

- **Nested JSON**: Many columns (`LocationDetails`, `DeviceDetail`, `ConditionalAccessPolicies`) contain nested JSON requiring `todynamic()` or `parse_json()`.
- **`column_ifexists()`** for optional columns (e.g., `RiskLevelDuringSignIn` requires Identity Protection P2): `extend RiskLevel = column_ifexists("RiskLevelDuringSignIn", "unknown")`.
- **ResultType codes** in `SigninLogs` are string-encoded — `"0"` = success, `"50126"` = invalid creds, `"50053"` = account locked, `"50057"` = account disabled, `"50074"` = MFA required, `"50076"` = MFA challenge failed, `"500121"` = MFA denied. Always reference the [Azure AD error codes documentation](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes) and comment the meaning inline.

---

## 3. Authoring KQL for Sentinel

> For language-level optimisation rules (filter ordering, operator selection, negation traps, parentheses), see **`kusto-query-language/SKILL.md`**. This section covers Sentinel specifics only.

### From hypothesis to queries

**Step 1 — decompose the behaviour** into discrete observable events in the identity / cloud / network domain. Each step that produces telemetry in a different table becomes a separate query.

**Step 2 — select tables** by behaviour:

| Behaviour | Primary table |
|---|---|
| User sign-in (interactive) | `SigninLogs` |
| User sign-in (non-interactive) | `AADNonInteractiveUserSignInLogs` |
| Azure AD configuration changes | `AuditLogs` |
| Azure resource operations | `AzureActivity` |
| Office 365 activity | `OfficeActivity` |
| Windows security events (4688, 4624, etc.) | `SecurityEvent` |
| Firewall/proxy/IDS/IPS | `CommonSecurityLog` |
| Linux syslog | `Syslog` |
| DNS resolution | `DnsEvents` |
| TI indicator matches | `ThreatIntelligenceIndicator` |
| Cloud app activity | `CloudAppEvents` |

**Step 3 — query body** with the mandatory header from `kusto-query-language`:

```kql
// ============================================================
// Hunt: <name>
// Purpose: <one-line description>
// Source intelligence: <reference>
// MITRE ATT&CK: <technique id - name>
// Platform: SENTINEL
// Precision: HIGH/MEDIUM/LOW | Recall risk: HIGH/MEDIUM/LOW
// ============================================================

let lookback = ago(30d);
let target_values = dynamic([...]);

SigninLogs
| where TimeGenerated > lookback
// ResultType 50126 = invalid creds; 50053 = account locked
| where ResultType in ("50126", "50053")
| where UserPrincipalName has_any (target_values)
| where not(condition)  // exclusion explained
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType
| order by TimeGenerated desc
```

### Sentinel-specific optimisation

- Use `has` over `contains` for indexed term search (terms ≥ 4 chars).
- Use `in` over `==` with `or` for value sets.
- Filter **before** `summarize` and `join` — Sentinel tables can be very large.
- For NRT rules, use `ingestion_time()` rather than `TimeGenerated` for temporal filtering.

---

## 4. Multi-query correlation patterns

Ten worked correlation patterns live in [references/Multi-Query-Correlation-Patterns.md](references/Multi-Query-Correlation-Patterns.md) — credential spray, risky sign-in to privilege escalation, OAuth consent versus baseline, sign-in and Azure resource correlation, appliance-log beaconing, schema-variant union, TI feed matching with `materialize` + `arg_max` + `coalesce`, session-window analysis, AiTM/BEC chains, and multi-technique identity union.

Load that file when you need a runnable query for one of these shapes. Read the pattern that matches the hypothesis rather than the whole file.

## 5. Sentinel-native operators worth knowing

| Operator | Purpose | When to use |
|---|---|---|
| `materialize()` | Cache subquery | Reused 2+ times (TI dedup, multi-stage chains) |
| `union isfuzzy=true` | Merge tables with different schemas | `SigninLogs` + `AADNonInteractiveUserSignInLogs` |
| `row_window_session()` | Dynamic session windowing | Brute-force clustering (better than `bin()`) |
| `series_decompose_anomalies()` | ML anomaly detection on time series | Sign-in volume spikes |
| `mv-apply` | Per-element array operations | Beaconing intervals, conditional access policy filtering |
| `coalesce()` | First non-null across columns | TI IP normalisation, optional fallbacks |
| `arg_max()` / `arg_min()` | Latest / earliest per group | Indicator dedup, latest event per user |
| `set_difference()` | Historical baseline comparison | New OAuth apps, new admin role holders |
| `top-nested N of X by Y` | Nested rarity analysis | Rare apps per user, rare locations per org |
| `ipv4_lookup()` / `ipv4_is_in_range()` | CIDR range matching | VPN range checks |
| `geo_info_from_ip_address()` | IP geolocation | City/country context without external lookup |
| `_GetWatchlist('name')` | Watchlist integration | Curated IOC/entity lists |

### `make-series` + anomaly detection

```kql
// Detect anomalous sign-in volume per user
let lookback = ago(30d);
SigninLogs
| where TimeGenerated > lookback
| where ResultType == "0"
| make-series LoginCount = count() on TimeGenerated from lookback to now() step 1h
    by UserPrincipalName
| extend (Anomalies, AnomalyScore, ExpectedCount) = series_decompose_anomalies(LoginCount, 1.5)
| mv-apply Anomalies on (where Anomalies == 1 | take 1)
| project UserPrincipalName, LoginCount, ExpectedCount, AnomalyScore
```

### `ingestion_time()` for delayed events

Some sources have significant ingestion delay (`OfficeActivity` can lag 15–60 minutes). For NRT and lag-aware hunts:

```kql
| where ingestion_time() > ago(1h)
| where TimeGenerated > ago(24h)  // safety bound on event age
```

### BehaviorAnalytics / IdentityInfo enrichment

```kql
// UEBA risk context
| join kind=leftouter (
    BehaviorAnalytics
    | where TimeGenerated > ago(7d)
    | summarize arg_max(TimeGenerated, InvestigationPriority, UsersInsights) by UserPrincipalName
) on UserPrincipalName

// Org context (department, manager, risk tags)
| join kind=leftouter (
    IdentityInfo
    | where TimeGenerated > ago(14d)
    | summarize arg_max(TimeGenerated, *) by AccountUPN
    | project AccountUPN, Department, JobTitle, Manager, Tags, IsAccountEnabled
) on $left.UserPrincipalName == $right.AccountUPN
```

---

## 6. False-positive engineering for Sentinel

```kql
// Tuning thresholds with guidance
let threshold_failures = 50;     // Default 50 — lower for privileged accounts, raise for service accounts
let threshold_unique_users = 5;
let lookback = ago(14d);

// Environment filters block
// --- BEGIN ENVIRONMENT FILTERS (customise per deployment) ---
| where UserPrincipalName !endswith "@external-partner.example"
| where AppDisplayName !in ("Known Internal App")
| where IPAddress !in (known_vpn_ranges)
// --- END ENVIRONMENT FILTERS ---

// column_ifexists for optional Identity Protection P2 fields
| extend RiskLevel = column_ifexists("RiskLevelDuringSignIn", "unknown")

// Alert dedup via SecurityAlert leftanti
| join kind=leftanti (
    SecurityAlert
    | where TimeGenerated > ago(7d)
    | where Status != "Dismissed"
    | extend AlertUser = tostring(parse_json(Entities)[0].UserPrincipalName)
    | project AlertUser
) on $left.UserPrincipalName == $right.AlertUser
```

---

## 7. Analytics rules

> Detection rule design (Scheduled and NRT) is covered in `detection-engineering/SKILL.md`. This section lists Sentinel-specific constraints only.

### Scheduled rules — configuration parameters

| Parameter | Range | Recommendation |
|---|---|---|
| Query interval | 5 min – 14 days | Match detection urgency |
| Lookback window | 5 min – 14 days | ≥ interval + ingestion buffer |
| Ingestion delay | ~5 min | Account for arrival lag |
| Alert threshold | Min/Max/Exact | Default: results > 0 |
| Event grouping | Group all / Per event | Per event = one alert per row (max 150) |
| Suppression | 1 h – 24 h | Prevent duplicate alerts for same entity |
| Query length | 1 – 10 000 chars | Move complex logic to `let` |

**Lookback rule**: lookback ≥ interval + ~5 min ingestion buffer. Example: 1 h interval → 1 h 15 min lookback.

### NRT rules — constraints

| Constraint | Detail |
|---|---|
| Max NRT rules per workspace | 50 |
| Max alerts per NRT rule | 30 single-event per run |
| Time filtering | Uses `ingestion_time()` automatically — **do not** add `TimeGenerated` filter |
| Table references | Multi-table allowed (previously single-table only) |
| Query length | 1 – 10 000 chars |
| Forbidden | `search *`, `union *` (explicit table references required) |

### Entity mapping

Map output columns to Sentinel entities for incident enrichment:

| Entity | Identifier columns |
|---|---|
| Account | `UserPrincipalName`, `AccountSid`, `AadUserId` |
| Host | `Computer`, `HostName`, `DnsDomain` |
| IP | `IPAddress`, `Address` |
| URL | `Url` |
| File | `FileName`, `FileHash` |
| Process | `ProcessId`, `CommandLine` |
| Azure Resource | `ResourceId` |
| DNS | `DomainName` |
| Mailbox | `MailboxPrimaryAddress` |

Include identifier columns in the `| project` output. Sentinel uses these to auto-populate the incident graph.

### Alert enrichment

```kql
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
    RiskLevel = RiskLevelDuringSignIn,         // custom detail
    FailedAttempts = FailureCount,              // custom detail
    AppName = AppDisplayName                    // custom detail
```

Title / description templates support `{{ColumnName}}` tokens:
- Title: `Suspicious sign-in by {{UserPrincipalName}} from {{Location}}`
- Description: `User {{UserPrincipalName}} signed in from {{IPAddress}} ({{Location}}) with risk level {{RiskLevel}}`

### Alert and incident grouping

| Feature | Detail |
|---|---|
| Event grouping | Group all (one alert/run) vs per event (max 150) |
| Entity-based grouping | Alerts from same rule + same entities → single incident |
| Grouping window | 5 min – 7 days |
| Reopen closed incidents | New matching alerts reopen the incident |

### MITRE ATT&CK mapping

Sentinel analytic rules support direct ATT&CK mapping in rule configuration — populate tactic and technique IDs in the rule UI/template, not just in inline comments.

### ASIM parsers

Use ASIM when:
- Detection should work across multiple data connectors.
- Rule shared across workspaces with different sources.
- Analytic rule will be templated for distribution.

Avoid ASIM when:
- Performance-critical (parsers add overhead from `union` + `project-rename`).
- Simple IOC lookups (direct table access is faster).
- Rule targets a single known data connector.

---

## 8. Quality checklist — Sentinel-specific

> Reject-list companion: [references/Anti-Patterns.md](references/Anti-Patterns.md) catalogues the query anti-patterns this checklist is meant to catch. Consult it when reviewing someone else's query.

> Language-level checks live in `kusto-query-language/SKILL.md`. Below are Sentinel-specific items.

- [ ] Platform tag set to **SENTINEL**.
- [ ] Table exists in the workspace (data connector configured).
- [ ] Time field is `TimeGenerated` (not `Timestamp`).
- [ ] No Defender column contamination (`Timestamp`, `AccountUpn`, `DeviceId` should not appear in Sentinel queries).
- [ ] `ResultType` codes commented with their meaning.
- [ ] Nested JSON extracted via `tostring()` / `todynamic()`.
- [ ] `column_ifexists()` used for optional columns.
- [ ] Analytic rule queries ≤ 10 000 chars.
- [ ] NRT rules: no `TimeGenerated` filter; ≤ 50 NRT rules per workspace.
- [ ] `materialize()` used when subquery referenced 2+ times.
- [ ] `union isfuzzy=true` when combining tables with different schemas.
- [ ] TI matching uses `arg_max()` dedup + `coalesce()` for IP normalisation.

---

## 9. Common Sentinel errors

| Error pattern | Cause | Fix |
|---|---|---|
| `Failed to resolve table` | Data connector not configured | Switch to available table or document gap |
| `Failed to resolve column` | Column doesn't exist in this table | Look up correct name in tenant table reference |
| `Timestamp > ago(7d)` rejected | Wrong time field name | Replace with `TimeGenerated` |
| `where DeviceId ==` rejected | Defender column in Sentinel | Replace with `Computer` or appropriate field |
| `Partial content` (HTTP 206) | Large result set truncated | Add `take`/`summarize` |

### Forensic lookback guidance

Sentinel retention is workspace-configurable (commonly 90–730 days), much longer than Defender's 30-day cap. Start with 14 days and extend if zero results.

| Hunt category | Recommended lookback |
|---|---|
| Persistence mechanisms | 30–90 days |
| Identity attacks | 14–30 days |
| Active C2 / beaconing | 7 days |
| Data exfiltration | 7–14 days |

### Table availability

Not all Sentinel tables exist in every workspace — they depend on data connectors. If a table query returns "Failed to resolve table", the connector is not configured. Document the gap rather than treat zero results as "threat not present."

---

## 10. Mapping into opentide MDR

When KQL is wired into a `configurations.sentinel` block in an opentide MDR object:

- **Description and tuning narrative** belong in the MDR `description` and `response.procedure` fields, not buried in inline comments.
- **Severity, response actions, playbook URIs** belong in `response.alert_severity` / `response.playbook` per MDR schema.
- **Inline KQL** still carries the mandatory header block, comment discipline, and FP engineering described above.
- Coordinate with `opentide-rule` for the structural placement and `detection-engineering` for hunt-to-rule conversion discipline.
