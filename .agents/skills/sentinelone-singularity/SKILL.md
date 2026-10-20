---
name: sentinelone-singularity
description: SentinelOne Singularity detection engineering — explicit distinction from Microsoft Sentinel, surface map across STAR Custom Logic (sensor-side behavioural rules), Deep Visibility (DVQL), Singularity Data Lake / PowerQuery (SDL alert configuration, scheduled queries, geo/math functions), exclusions and policies, Storyline ID-based correlation, AI Engine policy modes (detect / protect), SIEM ingestion patterns, and entity alignment for cross-platform correlation. Distilled from Sentinel-One/ai-siem community detection library. Use for sentinel_one-keyed configurations in opentide MDR objects — never confuse with microsoft-sentinel.
---

# SentinelOne Singularity — content authoring

> **Critical naming caveat**: "SentinelOne" is the vendor; "Sentinel" is the SentinelOne sensor product. This is **distinct from Microsoft Sentinel** (a SIEM). Detection content for SentinelOne goes into `configurations.sentinel_one` — never `configurations.sentinel`.

This skill encodes operational context for SentinelOne Singularity content authoring. The platform spans the **on-sensor AI Engine** (vendor-managed behavioural detection), **STAR Custom Logic** (customer-authored behavioural rules), **Deep Visibility** (event search), and **Singularity Data Lake / PowerQuery** (multi-source SIEM-like analytics).

---

## 1. Surface identification

| Surface | Purpose | Authoring language |
|---|---|---|
| **STAR Custom Logic** | Customer behavioural rules running on the agent or in the cloud | Rule builder (S1QL conditions) |
| **Deep Visibility** | On-platform hunting / search across endpoint telemetry | Deep Visibility Query Language (DVQL) |
| **Singularity Data Lake (SDL) / PowerQuery** | Multi-source analytics (Scalyr lineage) | PowerQuery (filter / parse / let / where / group / etc.) |
| **AI Engine policies** | Vendor-managed prevention/detection logic | Policy modes only (detect / protect) — not authored |
| **Exclusions** | Allow-listing for behavioural / static engines | Path / hash / signer / process |
| **Singularity Cloud Workload Security** | Cloud workload protection (Linux containers, K8s) | Separate engine — distinct policy surface |
| **Singularity Identity** | Identity-side detections (AD, Entra) | Separate add-on |
| **Singularity Hologram** | Deception (separate add-on) | Separate add-on |

The customer-authored detection authoring surfaces are primarily **STAR Custom Logic** and **PowerQuery scheduled queries** in SDL.

---

## 2. STAR Custom Logic

### Rule structure

| Component | Detail |
|---|---|
| Scope | Site / account / global |
| Rule type | Process, Network, File, DNS, Registry, Cross-process |
| Trigger | Alert / Mitigate (kill, quarantine, network isolate) |
| Severity | Low / Medium / High / Critical |
| Status | Draft / Active / Disabled |
| Cooldown | Suppression window per entity |

### Authoring discipline

- **Always start in Alert (detect-only) mode.** Never deploy a new STAR rule with mitigation enabled.
- **Cooldown set deliberately.** Without cooldown, behavioural triggers can fire repeatedly per entity.
- **Scope smallest first.** Test in a single site before account / global rollout.
- **MITRE mapping** populated explicitly in rule metadata (S1 supports technique tagging).
- **Rule description** documents intent, expected FP scenarios, triage steps — surfaced directly to analysts on alert.

### Storyline ID — the correlation key

SentinelOne assigns a **Storyline ID** to every causally linked group of events on an endpoint. This is S1's analogue of CrowdStrike's `ContextProcessId` or Defender's `ProcessUniqueId` — use it for chain correlation, not PIDs.

```
process.storyline.id = <UUID>
```

A confirmed Storyline corresponds to S1's view of "the same incident chain". When reviewing alerts, pivot on Storyline ID first — most analyst workflows live there.

---

## 3. Deep Visibility (DVQL)

DVQL is the search language for endpoint event hunting. It's neither KQL nor SPL — its own DSL.

### Idiomatic patterns

```
ProcessName Is "powershell.exe" AND CommandLine ContainsCIS "-EncodedCommand"
```

```
EventType = "DNS Resolved" AND DNS.Request EndsWith ".evil.example"
```

| DVQL construct | Notes |
|---|---|
| `Is`, `IsNot` | Equality |
| `Contains`, `ContainsCIS` (case-insensitive) | Substring |
| `In Contains Anycase`, `In Contains` | Multi-value |
| `EndsWith`, `StartsWith` | Anchored substring |
| `Matches` | Regex |
| `AND`, `OR`, `NOT` | Boolean (always parenthesise mixes) |
| Time scope | Set via UI / API time range, not inline |

### Process / Storyline pivots

- `process.storyline.id` — the per-process causal chain anchor.
- `agent.uuid` — sensor identifier.
- `endpoint.name` / `endpoint.ip` — host context.
- `user.name` — interactive user.

### Worked DVQL patterns

**Encoded PowerShell execution:**
```
EventType = "Process Creation"
    AND process.name Is "powershell.exe"
    AND process.command_line ContainsCIS "-encodedcommand"
    AND NOT process.parent.name Is "ccmexec.exe"
```

**LSASS access (credential dumping):**
```
EventType = "Process Creation"
    AND (process.command_line ContainsCIS "lsass"
        OR process.command_line ContainsCIS "sekurlsa")
    AND process.name In Contains Anycase ("rundll32.exe", "procdump.exe", "mimikatz.exe")
```

**Named pipe C2 (Cobalt Strike default patterns):**
```
EventType = "Named Pipe Creation"
    AND (tgt.file.path Matches "\\\\MSSE-.*"
        OR tgt.file.path Matches "\\\\postex_.*"
        OR tgt.file.path Matches "\\\\msagent_.*")
```

**Suspicious outbound connection to rare port:**
```
EventType = "IP Connect"
    AND network.direction Is "OUTGOING"
    AND dst.port.number In (4444, 8443, 8080, 1337)
    AND NOT dst.ip.address StartsWith "10."
    AND NOT dst.ip.address StartsWith "172.16."
    AND NOT dst.ip.address StartsWith "192.168."
```

**Storyline pivot (expand from a known-bad process):**
```
process.storyline.id Is "<UUID from initial alert>"
```

This returns the entire causal chain — all processes, files, network connections, and registry changes linked to the same Storyline.

---

## 4. Singularity Data Lake / PowerQuery

The SDL surface exposes a Scalyr-derived analytics engine via PowerQuery. Multi-source ingestion (cloud, identity, network, third-party logs).

### PowerQuery essentials

```
$source != "" agentName == "S1Agent" message contains "powershell.exe"
| parse "User: $user$"
| let domain = split(user, "\\")[0]
| group count() by domain
| sort -count
```

| PowerQuery construct | Notes |
|---|---|
| Filter syntax | Field equality / contains / regex with implicit `AND` between predicates |
| `| parse` | Extract fields via inline pattern |
| `| let` | Computed field |
| `| filter` | Post-parse filtering |
| `| group X by Y` | Aggregation |
| `| transaction` | Group sequential events into transactions |
| `| join` | Cross-stream joins |

PowerQuery's pipeline shape is closer to SPL than KQL — work flows top-down through commands. Filtering as early as possible against indexed fields remains the dominant performance rule.

### Worked PowerQuery patterns

**Brute-force detection (authentication failures):**
```
$source != "" event.type == "authentication" event.outcome == "failure"
| group count() as fail_count by user.name, source.ip
| filter fail_count > 50
| sort -fail_count
```

**Beaconing detection (connection interval consistency):**
```
$source != "" event.type == "network_connection" network.direction == "outgoing"
| group count() as conn_count, min(timestamp) as first, max(timestamp) as last
    by endpoint.name, dst.ip.address
| filter conn_count > 20
| let avg_interval = (last - first) / (conn_count - 1)
| sort -conn_count
```

**Rare process per endpoint (anomaly):**
```
$source != "" event.type == "process_creation"
| group count() as exec_count, countDistinct(endpoint.name) as host_count
    by process.name
| filter host_count <= 3
| sort host_count
```

### SDL alert configuration

PowerQuery detections in SDL are defined as alert configurations (`.conf` JSON format). Structure:

```json
{
  "alerts": [
    {
      "description": "Excessive Failed Logins",
      "evaluationFrequencyMinutes": 15,
      "gracePeriodMinutes": 0,
      "renotifyPeriodMinutes": 60,
      "resolutionDelayMinutes": 0,
      "trigger": "8 hours(event.type='SignInLogs' response.error_message contains 'failed' | group total=count() by user.name | filter total > 5)",
      "type": "GROUPED"
    }
  ]
}
```

| Field | Description |
|---|---|
| `trigger` | PowerQuery expression with time window prefix (e.g., `8 hours(...)`, `1 days(...)`, `10 minutes(...)`) |
| `evaluationFrequencyMinutes` | How often the alert evaluates |
| `gracePeriodMinutes` | Delay before first alert fires |
| `renotifyPeriodMinutes` | Minimum interval between re-notifications |
| `resolutionDelayMinutes` | Delay before auto-resolving |
| `type` | `"GROUPED"` for per-entity alerting, omit for global |

### PowerQuery function reference

| Function | Purpose | Example |
|---|---|---|
| `count()` | Event count | `group count() by user.name` |
| `countDistinct(field)` | Distinct count | `countDistinct(endpoint.name) as host_count` |
| `min(field)` / `max(field)` | Range bounds | `min(timestamp) as first` |
| `sum(field)` / `avg(field)` | Arithmetic | `sum(bytes) as total_bytes` |
| `split(field, delim)` | String split | `split(user, "\\\\")[0]` |
| `geo_ip_country(ip)` | IP to country | `geo_ip_country(src.ip.address)` |
| `geo_ip_location(ip)` | IP to lat/lon | `geo_ip_location(src.ip.address)` |
| `geo_distance(loc1, loc2)` | Distance in km | `geo_distance(geo_ip_location(a.ip), geo_ip_location(b.ip))` |
| `running_sum(n)` | Running total | `running_sum(1)` for row numbering |
| `abs(n)` | Absolute value | `abs(b.timestamp - a.timestamp)` |
| `parse "pattern"` | Field extraction | `parse "User: $user$"` |
| `columns` | Field projection | `columns timestamp, user.name, src.ip.address` |
| `sort` | Ordering | `sort -count` (descending) |
| `transaction` | Group sequential events | Transaction-based correlation |
| `join` | Cross-stream join | `join a=(...), b=(...) on key` |

### Multi-source filtering

SDL ingests from multiple data sources. Use `dataSource.name` to filter:

```
dataSource.name='Azure Event Hub' event.type='SignInLogs'
```

Common data sources: `S1Agent` (endpoint), `Azure Event Hub`, `AWS CloudTrail`, `Okta`, `Office 365`, custom integrations.

### Scheduled queries

PowerQuery searches can be scheduled to fire alerts; treat with the same discipline as Sentinel scheduled rules:

- Severity calibrated.
- Suppression / dedup configured.
- Output schema deliberate (fields fed downstream).
- Tested under the production lookback window.

---

## 5. AI Engine policy modes

The vendor-managed AI Engine runs across multiple sub-engines:

| Engine | Function |
|---|---|
| Static AI | Pre-execution file analysis |
| Behavioural AI | Real-time runtime monitoring |
| Documents | Document-borne malware |
| Lateral movement | Cross-host correlation |
| Anti-Exploitation / Application Control | Memory protection |
| (others, version-dependent) | Reputation, anti-tamper, etc. |

Policy modes:

| Mode | Behaviour |
|---|---|
| **Detect** | Alert only |
| **Protect (Kill / Quarantine)** | Auto-mitigate |

Detection content authors **do not modify** AI Engine logic — only policy assignment. Exclusions and overrides are the customisation surface.

---

## 6. Exclusions

Exclusions are powerful and risky. Six types:

| Type | Scope |
|---|---|
| **Path** | Allow a directory / file pattern |
| **Hash** | Allow a SHA1 / SHA256 |
| **Signer** | Allow a digital certificate |
| **Process** | Suppress a specific process |
| **File Type** | Allow specific extensions |
| **Browser** | Allow browser-specific behaviour |

**Exclusion authoring discipline**:

- **Tightest scope.** Path exclusions specifying the executable name beat directory-wide exclusions.
- **Operating mode set deliberately.** Suppress alerts? Suppress kill? Both? Each is a separate exclusion mode.
- **Audit trail.** Every exclusion carries a description with provenance (ticket reference, requester, date, expiry plan).
- **Periodic review.** Stale exclusions become persistent attacker-friendly territory. Review quarterly.

When authoring detection content, document **expected exclusion patterns** in the rule description so SOC engineers can manage allow-lists without retuning the rule.

---

## 7. Sensor capability boundaries

| Capability | Windows | macOS | Linux | K8s |
|---|---|---|---|---|
| Process / file / network | Full | Full | Full | Container-aware (CWS) |
| Registry | Full | n/a | n/a | n/a |
| DNS | Full | Full | Limited | Limited |
| Memory protection | Full | Full | Limited | n/a |
| Storyline causality | Full | Full | Full | Full |

Cloud Workload Security (CWS) for Linux containers / K8s is a **separate sensor** with its own coverage model. Detection content that targets node OS vs container interior must declare which.

---

## 8. SIEM ingestion patterns

> Table/index names are SIEM-specific. Consult your SIEM's SentinelOne integration documentation for exact configurations.

| S1 source | Telemetry type | Ingestion method | Notes |
|---|---|---|---|
| Threats / Alerts | Detection alerts (AI Engine, STAR, watchlist) | API polling or Syslog CEF forwarding | Primary alert source |
| Deep Visibility events | Process, file, network, registry, DNS events | API export or SDL Data Lake | Requires Complete SKU |
| Activity Log | Admin actions, policy changes | API polling | Always available |
| Singularity Data Lake | Multi-source analytics data | Native SDL ingestion | PowerQuery runs natively |
| Threat Intelligence | IOC matches | API or STIX/TAXII feed | Requires TI add-on |

### Syslog / CEF forwarding

SentinelOne supports Syslog forwarding in CEF format for threat alerts. This is the simplest integration method for traditional SIEMs. Configure in Settings → Integrations → Syslog.

### API-based ingestion

For richer data (Deep Visibility events, full threat context), use the SentinelOne API. The `/threats`, `/activities`, and `/deep-visibility` endpoints provide structured JSON.

---

## 9. Entity identifier alignment

| Concept | SentinelOne | Microsoft Defender | CrowdStrike |
|---|---|---|---|
| Host | `agent.uuid`, `endpoint.name` | `DeviceId`, `DeviceName` | `aid`, `ComputerName` |
| User | `user.name` | `AccountName`, `AccountUpn` | `UserName` |
| Process correlation | `process.storyline.id` | `ProcessUniqueId` | `ContextProcessId_decimal` |
| Hash | `tgt.process.image.sha256` | `SHA256` | `SHA256HashData` |
| Network | `dst.ip.address` | `RemoteIP` | `RemoteAddressIP4` |

Cross-platform correlation happens at the SOAR / SIEM layer, never via direct cross-vendor joins.

---

## 10. Mapping into opentide MDR

When SentinelOne content lives in `configurations.sentinel_one`:

- **Identify the surface** (STAR Custom Logic / DVQL hunt / PowerQuery scheduled / Exclusion).
- **Storyline-based correlation** preferred over PID/timestamp.
- **MITRE mapping** populated in both rule metadata and MDR `description`.
- **Sensor / SKU coverage** declared (endpoint vs CWS vs Identity).
- **Expected exclusion patterns** documented to support SOC engineer maintenance.
- Coordinate with `opentide-rule` for placement and `detection-engineering` for lifecycle.

---

## 11. Quality checklist

- [ ] Surface identified (STAR / DVQL / PowerQuery scheduled / SDL alert / Exclusion).
- [ ] STAR rules deployed in Alert mode first; cooldown set.
- [ ] DVQL pivots on `process.storyline.id`, not PID.
- [ ] PowerQuery filters as early as possible, indexed fields first.
- [ ] SDL alert `evaluationFrequencyMinutes` and `renotifyPeriodMinutes` set deliberately.
- [ ] SDL alert `type: "GROUPED"` used for per-entity alerting where appropriate.
- [ ] `dataSource.name` filter used in multi-source SDL queries.
- [ ] AI Engine policy mode (Detect / Protect) deliberate.
- [ ] Exclusions tight-scoped with audit metadata.
- [ ] Sensor / SKU coverage declared in MDR description (endpoint vs CWS vs Identity).
- [ ] MITRE mapping in rule metadata + MDR description.
- [ ] FP / triage guidance written for analysts seeing the alert.
- [ ] SIEM ingestion method documented (Syslog CEF / API / SDL native).
- [ ] Naming caveat respected: `sentinel_one` config key, NOT `sentinel`.

---

## 12. Reference catalogues

- `references/DVQL-Field-Reference.md` — DVQL event types, field names by category (process, endpoint, network, DNS, file, registry, module), operator syntax, PowerQuery differences, and cross-platform entity alignment.
