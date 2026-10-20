---
name: microsoft-defender-endpoint
description: Microsoft Defender for Endpoint (MDE) Advanced Hunting authoring guidance — Device*/Email*/Identity* table schemas, Timestamp discipline, ProcessUniqueId vs PID for temporal joins, FileProfile() prevalence enrichment with null handling, AdditionalFields parsing, mandatory output columns for custom detection rules (Timestamp/DeviceId/ReportId), NRT single-table/no-comment constraints, retention boundaries, named-pipe and DGA detection patterns. Always pair with kusto-query-language for language-level optimisation. Use for configurations.defender_for_endpoint blocks in opentide MDR objects and Defender-first hypotheses.
---

# Microsoft Defender for Endpoint — Advanced Hunting

Author and review KQL for Microsoft Defender Advanced Hunting (M365 Defender). This skill covers Defender-native tables and operational specifics; for identity/cloud/SaaS/network telemetry use **`microsoft-sentinel`**; for vendor-neutral KQL optimisation use **`kusto-query-language`**.

---

## 1. When to use Defender vs Sentinel

| Telemetry domain | Platform | Primary tables |
|---|---|---|
| Endpoint processes / file ops / registry | **Defender** | `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceRegistryEvents` |
| Device-level network connections | **Defender** | `DeviceNetworkEvents`, `DeviceNetworkInfo` |
| Email (M365 Defender) | **Defender** | `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `EmailPostDeliveryEvents` |
| Device inventory & compliance | **Defender** | `DeviceInfo`, `DeviceLogonEvents` |
| DLL / module loads | **Defender** | `DeviceImageLoadEvents` |
| Scheduled tasks, WMI, misc events | **Defender** | `DeviceEvents` |
| Code-signing validation | **Defender** | `DeviceFileCertificateInfo` |
| URL clicks (M365) | **Defender** | `UrlClickEvents` |
| Identity & authentication | **Sentinel** | `SigninLogs`, `AuditLogs` |
| Azure / cloud infrastructure | **Sentinel** | `AzureActivity`, `AzureDiagnostics` |
| SaaS activity | **Sentinel** | `OfficeActivity`, `CloudAppEvents` |
| Network appliances | **Sentinel** | `CommonSecurityLog`, `Syslog` |

**Cross-platform hypotheses** (e.g., credential phishing → endpoint execution): generate **separate queries per platform** with the correct platform tag. Do not attempt cross-platform joins.

---

## 2. Column authority — non-negotiable

> The tenant-specific table schema reference (typically `references/MDE-Tables.md` in your content repo) is the **only** source of truth for Defender table columns. Do not invent, guess, or recall column names from memory — always look them up.

### Procedure
1. Open the tenant's table reference.
2. Find the target table and confirm the column appears in its key columns.

### Critical Defender ↔ Sentinel column differences

Wrong column = guaranteed `SYNTAX_ERROR`. Common contamination traps:

| Concept | Defender column | Sentinel column |
|---|---|---|
| Timestamp | `Timestamp` | `TimeGenerated` |
| Device identifier | `DeviceId` (UUID) | `Computer` (hostname) |
| User account | `AccountName` | `SubjectUserName` / `TargetUserName` |
| User principal | `AccountUpn` | `UserPrincipalName` |
| Process command line | `ProcessCommandLine` | `CommandLine` |
| Source IP | `RemoteIP` | `IpAddress` / `CallerIpAddress` |

**Do not copy Sentinel column names into Defender queries.** Each table within Defender also has its own column subset — `AccountUpn` exists in `DeviceProcessEvents` but **not** in `DeviceNetworkEvents` (use `InitiatingProcessAccountName` there).

---

## 3. Authoring KQL for Defender

> For language-level optimisation, see **`kusto-query-language/SKILL.md`**.

### From hypothesis to queries

**Step 1 — decompose** the hypothesis into discrete observable telemetry events. Each step that produces telemetry in a different table becomes a separate query.

**Step 2 — select tables** by behaviour:

| Behaviour | Primary table |
|---|---|
| Process execution, command lines | `DeviceProcessEvents` |
| File creation/modification/deletion | `DeviceFileEvents` |
| Network connections (device-level) | `DeviceNetworkEvents` |
| DLL / module loads | `DeviceImageLoadEvents` |
| Registry changes | `DeviceRegistryEvents` |
| Logon activity (device) | `DeviceLogonEvents` |
| Scheduled tasks, WMI, named pipes, etc. | `DeviceEvents` |
| Email delivery | `EmailEvents` (+ joins) |
| Code-signing validation | `DeviceFileCertificateInfo` |

**Step 3 — query body** with the mandatory header from `kusto-query-language`:

```kql
// ============================================================
// Hunt: <name>
// Purpose: <one-line description>
// Source intelligence: <reference>
// MITRE ATT&CK: <technique id - name>
// Platform: DEFENDER
// Precision: HIGH/MEDIUM/LOW | Recall risk: HIGH/MEDIUM/LOW
// ============================================================

let lookback = ago(30d);
let target_values = dynamic([...]);

DeviceProcessEvents
| where Timestamp > lookback
| where FileName in~ ("target.exe")
| where ProcessCommandLine has_any (target_values)
| where not(condition)  // exclusion explained
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

### Defender-specific optimisation

- Pre-filter `ProcessCommandLine` with `has_any` **before** `parse`/`extract`/`matches regex` — 10–100× faster on this high-cardinality column.
- Use `invoke FileProfile(SHA1, 1000)` **after** other filters to minimise enrichment lookups.
- Parse `AdditionalFields` with `parse_json()` only **after** filtering on `ActionType` — avoids parsing millions of irrelevant rows.

---

## 4. Multi-query correlation patterns

Thirteen worked correlation patterns live in [references/Multi-Query-Correlation-Patterns.md](references/Multi-Query-Correlation-Patterns.md) — sequential process to network, temporal joins, statistical anomaly, beaconing, prevalence hunting, baseline deviation, process-chain reconstruction, `materialize()` multi-stage, `leftanti` exclusion chains, DGA domains, certificate supply chain, multi-technique union, and named-pipe C2.

Load that file when you need a runnable query for one of these shapes. Read the pattern that matches the hypothesis rather than the whole file.

## 5. `AdditionalFields` parsing

Many `DeviceEvents` `ActionType`s store structured data in the `AdditionalFields` JSON column. Always parse:

```kql
| extend ParsedFields = parse_json(AdditionalFields)
| extend FieldValue = tostring(ParsedFields.FieldName)
```

Key action types with `AdditionalFields`:

| ActionType | Common fields |
|---|---|
| `NamedPipeEvent` | `PipeName`, `NamedPipeEnd` |
| `DnsQueryResponse` | `DnsQueryString`, `DnsQueryType` |
| `ServiceInstalled` | `ServiceName`, `ServiceType` |
| `PowerShellCommand` | `Command`, `ScriptBlockText` |

Always filter on `ActionType` first; only then parse `AdditionalFields` to avoid expensive parsing across the full table.

---

## 6. False-positive engineering for Defender

```kql
// Tuning thresholds with guidance
let threshold_connections = 50;     // Default 50 — lower for sensitive segments, raise for noisy networks
let threshold_unique_targets = 10;
let lookback = ago(7d);

// Environment filters
// --- BEGIN ENVIRONMENT FILTERS (customise per deployment) ---
| where DeviceName !startswith "SCAN-"            // exclude vulnerability scanners
| where AccountName !in~ ("svc_monitoring")       // exclude service accounts
// --- END ENVIRONMENT FILTERS ---

// Alert dedup via AlertInfo leftanti
| join kind=leftanti (
    AlertInfo
    | where Timestamp > ago(7d)
    | where Title has "related alert title"
    | project DeviceId
) on DeviceId

// net.exe / net1.exe deduplication: Windows maps net.exe to net1.exe internally
| where not(FileName =~ "net1.exe" and InitiatingProcessFileName =~ "net.exe")
```

---

## 7. Custom detection rules (Defender)

> Detection rule design is covered in `detection-engineering/SKILL.md`. This section lists Defender-specific constraints only.

### Required output columns

Custom detection rules in Defender XDR enforce specific columns. Missing required columns → rule creation fails (unlike hunting queries where output columns are flexible).

**Endpoint tables** (`DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, etc.):

| Column | Required | Purpose |
|---|---|---|
| `Timestamp` | YES | Alert timestamp |
| `DeviceId` | YES | Maps alert to device entity |
| `ReportId` | YES | Event deduplication |

**Non-endpoint tables** (`EmailEvents`, `IdentityLogonEvents`, etc.):

| Column | Required | Purpose |
|---|---|---|
| `Timestamp` | YES | Alert timestamp |
| `ReportId` | YES | Event deduplication |

Detection rule queries MUST include these in `| project`. Hunting queries don't — but detection rules enforce the schema.

### Rule frequency options

| Frequency | Lookback window | Use when |
|---|---|---|
| Every 24 h | 48 h | Low-priority broad behavioural detections |
| Every 12 h | 24 h | Standard detections |
| Every 3 h | 6 h | Medium-priority detections |
| Every 1 h | 2 h | High-priority, time-sensitive detections |
| Continuous (NRT) | Near-real-time | Critical, immediate-response detections |
| Custom | Configurable | Specific operational requirements |

The detection engine manages lookback overlap. **Do not** add explicit `Timestamp > ago()` filters to detection rule queries.

### NRT constraints

NRT runs continuously but is strictly limited:

| Constraint | Detail |
|---|---|
| Single table only | No `join`, `union`, multi-table references |
| No KQL comments | `//` comments cause NRT compilation errors |
| No `externaldata()` | External references unsupported |

**NRT-supported tables**:

| Category | Tables |
|---|---|
| Endpoint | `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceImageLoadEvents`, `DeviceEvents` |
| Email | `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `EmailPostDeliveryEvents` |
| Identity / Cloud | `CloudAppEvents`, `IdentityLogonEvents`, `IdentityDirectoryEvents` |

**NRT example**:

```kql
DeviceProcessEvents
| where FileName in~ ("certutil.exe", "bitsadmin.exe")
| where ProcessCommandLine has_any ("-urlcache", "-decode", "/transfer")
| project Timestamp, DeviceId, ReportId, DeviceName, AccountName,
    FileName, ProcessCommandLine, InitiatingProcessFileName
```

No comments, no joins, no explicit time filter — the NRT engine manages all of this.

### Entity mapping

Map output columns to entity types for Automated Investigation graphs:

| Entity | As impacted asset | As evidence | Required columns |
|---|---|---|---|
| Device | YES | YES | `DeviceId`, `DeviceName` |
| User | YES | YES | `AccountSid`, `AccountName`, `AccountUpn` |
| File | — | YES | `SHA256`, `FileName`, `FolderPath` |
| Process | — | YES | `ProcessId`, `ProcessCommandLine` |
| IP | — | YES | `RemoteIP` |
| URL | — | YES | `RemoteUrl` |
| Mailbox | YES | YES | `RecipientEmailAddress` |

### Alert enrichment

**Custom details** — up to 20 key-value pairs (max 4 KB total). Include extra columns in the query output; they appear as custom fields:

```kql
| project Timestamp, DeviceId, ReportId, DeviceName, AccountName,
    FileName, ProcessCommandLine,
    DecodedPayload,        // custom detail: decoded base64 content
    ParentProcessChain     // custom detail: full process ancestry
```

**Dynamic title / description** — `{{ColumnName}}` tokens supported:

- Title: `Suspicious {{FileName}} execution on {{DeviceName}}`
- Description: `User {{AccountName}} executed {{FileName}} with command line: {{ProcessCommandLine}}`

### Response actions

| Target | Available actions |
|---|---|
| Device | Isolate, run AV scan, restrict app execution, initiate investigation |
| File | Quarantine, allow/block |
| User | Mark as compromised, disable user, force password reset |
| Email | Move to junk, delete, soft delete |

**Conservative defaults**: Use **"Initiate investigation"** for new detections. Reserve isolation/quarantine for high-confidence critical-severity rules. Escalate after stability is established in production.

### Alert limits

- Max **150 alerts per rule run**. Excess results are dropped silently — design queries to stay below.
- Duplicate handling: rows with the same `ReportId` + `Timestamp` as an existing alert are deduplicated automatically.

### Detection rule template

```kql
// Detection: <Detection Name>
// Frequency: Every N hours | Continuous (NRT)
// Severity: Informational | Low | Medium | High | Critical
// MITRE: <Technique ID - Technique Name>
// Entity mapping: Device (DeviceId), User (AccountSid), <other entities>
DeviceProcessEvents
| where /* filters — no explicit time filter, engine manages lookback */
| where /* additional behavioural filters */
| where not(/* false-positive exclusions */)
| project Timestamp, DeviceId, ReportId, DeviceName, AccountName, AccountSid,
    FileName, ProcessCommandLine, FolderPath,
    InitiatingProcessFileName, InitiatingProcessCommandLine
```

---

## 8. Quality checklist — Defender-specific

> Reject-list companion: [references/Anti-Patterns.md](references/Anti-Patterns.md) catalogues the query anti-patterns this checklist is meant to catch. Consult it when reviewing someone else's query.

> Language-level checks live in `kusto-query-language/SKILL.md`.

- [ ] Platform tag set to **DEFENDER**.
- [ ] Table exists in tenant (verified against tenant table reference).
- [ ] Time field is `Timestamp` (not `TimeGenerated`).
- [ ] No Sentinel column contamination (`TimeGenerated`, `UserPrincipalName`, `Computer` should not appear in Defender queries).
- [ ] Detection rules include mandatory output columns: `Timestamp`, `DeviceId`, `ReportId`.
- [ ] NRT rules: single table, no comments, no joins.
- [ ] `materialize()` used when subquery referenced 2+ times.
- [ ] `AdditionalFields` parsed via `parse_json()` after `ActionType` filter.
- [ ] `FileProfile()` results handle `isempty()` for missing prevalence.
- [ ] Multi-table joins time-windowed; PIDs replaced with `*UniqueId` where applicable.

---

## 9. Common Defender errors

| Error pattern | Cause | Fix |
|---|---|---|
| `The query references unknown table` | Table not in tenant schema | Verify against tenant table reference |
| `Failed to resolve column` | Column doesn't exist in this table | Look up correct column |
| `TimeGenerated > ago(7d)` rejected | Wrong time field | Replace with `Timestamp` |
| `Query exceeds the allowed limits` | Too many rows / too long | Add `take`, `summarize`, tighter time filter |
| HTTP 429 | Rate limit exceeded | Wait ~65 s; stop if persistent |

### Forensic lookback

| Hunt category | Default lookback | Rationale |
|---|---|---|
| Persistence mechanisms | 30 days | Defender retention cap |
| Lateral movement | 30 days | Active movement |
| Initial access / phishing | 14–30 days | Campaign windows |
| Active C2 beaconing | 7 days | Current state |
| Data exfiltration | 7–14 days | Recent activity, high data volume |

> Defender retention is typically capped at 30 days. Sentinel allows longer lookbacks via the same `Device*` tables ingested through the M365 Defender connector — when 30 days is insufficient, write a Sentinel-side query against the same logical schema.

---

## 10. Mapping into opentide MDR

When KQL is wired into a `configurations.defender_for_endpoint` block in an opentide MDR object:

- Description, tuning narrative, alert severity, response actions belong in the MDR `description` and `response.*` fields per MDR schema.
- Inline KQL still carries the mandatory header block, comment discipline, and FP engineering above.
- Coordinate with `opentide-rule` for structural placement and `detection-engineering` for hunt-to-rule conversion discipline.
