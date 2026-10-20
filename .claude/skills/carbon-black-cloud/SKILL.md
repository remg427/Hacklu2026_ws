---
name: carbon-black-cloud
description: VMware Carbon Black Cloud Enterprise EDR authoring guidance — distinguishes process search query syntax (CBC search language) from watchlist feeds, scheduled searches, and live response. Covers indicator vs IOC discipline, watchlist subscription model, alert override / interrupt, sensor capability boundaries, and entity identifier alignment for cross-platform correlation. Use for carbon_black_cloud-keyed configurations in opentide MDR objects.
---

# Carbon Black Cloud Enterprise EDR — content authoring

This skill encodes operational context for authoring detection content in `configurations.carbon_black_cloud` blocks of opentide MDR objects. Carbon Black Cloud (CBC) Enterprise EDR (formerly CB ThreatHunter) is the relevant product surface; older CB Response (on-prem) is **not** the same product.

---

## 1. Surface identification

| Surface | Used for |
|---|---|
| **Process Search (Investigate)** | Ad-hoc hunting via the search bar / API |
| **Watchlists** | Recurring alert generation backed by Reports / IOCs |
| **Scheduled Searches** (via API) | Custom periodic queries with action hooks |
| **Alerts** | Notable events from Watchlist hits, sensor IOC matches, NGAV detections |
| **Live Response** | Constrained shell over the sensor for IR |
| **Threat Intel Feeds** | Subscribed third-party / Carbon Black-curated indicator streams |

CBC's primary detection authoring surface is **Watchlists** (curated collections of Reports, each containing one or more IOCs/queries). Scheduled searches are a complementary mechanism for query-based detections that need richer aggregation.

---

## 2. Process search query syntax

CBC search syntax is Lucene-based (Solr under the hood). Field-level filters with boolean operators:

```
process_name:powershell.exe AND process_cmdline:*-EncodedCommand*
```

```
device_os:WINDOWS AND netconn_action:ACTION_CONNECTION_CREATE
    AND netconn_remote_port:443 AND -netconn_remote_ipv4:10.0.0.0/8
```

| Operator | Meaning |
|---|---|
| `field:value` | Equality |
| `field:*partial*` | Wildcard match |
| `AND`, `OR`, `NOT` (or `-`) | Boolean |
| `field:[a TO b]` | Range |
| `()` | Grouping |

**Process fields**:

| Field | Description |
|---|---|
| `process_name` | Executable name (lowercase path) |
| `process_cmdline` | Full command line |
| `process_hash` | SHA256 and MD5 hashes (array) |
| `process_guid` | Stable per-process identifier (primary correlation key) |
| `process_pid` | Process ID (array — may recycle) |
| `process_username` | User context |
| `process_original_filename` | PE original filename (anti-rename detection) |
| `process_effective_reputation` | CBC reputation: `TRUSTED_WHITE_LIST`, `LOCAL_WHITE`, `NOT_LISTED`, `KNOWN_MALWARE`, `SUSPECT_MALWARE`, `PUP`, `ADAPTIVE_WHITE_LIST`, `COMPANY_BLACK_LIST` |
| `process_elevated` | Boolean — running with elevated privileges |
| `process_integrity_level` | `SYSTEM`, `HIGH`, `MEDIUM`, `LOW` |
| `process_company_name` | PE company name metadata |
| `process_internal_name` | PE internal name |
| `process_service_name` | Windows service name (if applicable) |
| `process_start_time` | ISO 8601 process start timestamp |

**Parent fields**: `parent_name`, `parent_cmdline`, `parent_hash`, `parent_guid`, `parent_pid`, `parent_reputation`, `parent_effective_reputation`

**Device fields**: `device_name`, `device_id`, `device_os` (`WINDOWS`/`LINUX`/`MAC`), `device_policy`, `device_policy_id`, `device_external_ip`, `device_internal_ip`, `device_sensor_version`, `device_target_priority`, `device_location`

**Event count fields** (per-process aggregates): `childproc_count`, `crossproc_count`, `filemod_count`, `modload_count`, `netconn_count`, `regmod_count`, `scriptload_count`

**Time scope**: Set via `time_range` in API (`window: "-2w"`, or `start`/`end` ISO 8601), or via the search interface time picker.

### Event type taxonomy

Each process has associated events of specific types:

| Event type | Key fields | Detection use |
|---|---|---|
| `childproc` | `childproc_name`, `childproc_cmdline`, `childproc_guid` | Process spawning chains |
| `crossproc` | `crossproc_name`, `crossproc_action` (`ACTION_OPEN_PROCESS_HANDLE`) | Process injection, LSASS access |
| `filemod` | `filemod_name`, `filemod_action` | File creation/modification/deletion |
| `modload` | `modload_name`, `modload_md5`, `modload_sha256` | DLL loading, side-loading |
| `netconn` | `netconn_action`, `netconn_remote_ipv4`, `netconn_remote_port`, `netconn_protocol`, `netconn_local_port`, `netconn_inbound` | C2, lateral movement, exfiltration |
| `regmod` | `regmod_name`, `regmod_action` | Registry persistence, configuration changes |
| `scriptload` | `scriptload_name`, `scriptload_content`, `fileless_scriptload_cmdline` | Script execution, AMSI content |

### Critical query patterns

**Enriched event exclusion**: Append `-enriched:true` to watchlist IOC queries to avoid duplicate hits from enriched events.

```
process_name:powershell.exe AND process_cmdline:*-EncodedCommand* -enriched:true
```

**Renamed binary detection**: Use `process_original_filename` to catch renamed executables:

```
!process_name:sethc.exe AND process_original_filename:sethc.exe
```

**Event count thresholds**: Filter processes by activity volume:

```
process_name:wscript.exe AND netconn_count:[1 TO *]
```

**Reputation filtering**: Focus on unknown or untrusted binaries:

```
process_effective_reputation:NOT_LISTED AND netconn_count:[1 TO *]
```

---

## 3. Watchlists, Reports, and IOCs

CBC's authoring hierarchy:

```
Watchlist  ──contains──▶  Report  ──contains──▶  IOC(s)
                                              │  ├─ query (saved process search)
                                              │  ├─ equality (atomic value match)
                                              │  └─ regex (pattern match)
```

| Concept | Description |
|---|---|
| **Watchlist** | Subscription unit — a tenant subscribes to a Watchlist and receives alerts for any matching report |
| **Report** | A named detection — title, description, severity, IOCs, optional tags, optional MITRE mapping |
| **IOC** | The atomic match — query, equality, or regex |

### Authoring discipline

- **One TTP per Report.** Do not pack multiple unrelated detections into a single Report (CBC's analogue of AP-H2 Kitchen Sink).
- **Severity calibration.** Reserve Severity 8–10 for high-confidence detections that justify analyst paging. Most behavioural detections sit at Severity 5–7.
- **MITRE mapping** populated in the Report metadata, not just inline.
- **Report tags** for taxonomy (e.g. `T1059`, `Initial Access`, `RansomwarePrecursor`).
- **Description prose** documents intent, FP scenarios, and triage steps — CBC alerts surface this directly to analysts.

### Watchlist hygiene

- Custom watchlists scoped to a tenant; subscribed alongside vendor watchlists.
- Periodic review of report-level alert volume — high-volume reports tune or disable.
- Keep IOC-only reports separate from query reports; they have different update cadences.

---

## 4. Scheduled searches (API-driven)

For detections requiring aggregation across many events (e.g. beaconing, frequency-based anomaly), use the Scheduled Search API:

| Field | Detail |
|---|---|
| `query` | CBC process search query |
| `interval` | Cadence (configurable) |
| `device_filter` | Optional scope filter |
| `notification_action` | Email / webhook / SOAR endpoint on hit |

Scheduled searches do **not** generate alerts in the alert pipeline by default — they fire notifications. For alert-pipeline integration, the workflow typically writes results back into a Watchlist Report or SIEM.

---

## 5. Sensor capability boundaries

| Capability | Windows | macOS | Linux |
|---|---|---|---|
| Process tree | Full | Full | Full |
| Command line | Full | Full | Full (per kernel) |
| File modifications | Full | Full | Full |
| Network connections | Full | Full | Full |
| Registry | Full | n/a | n/a |
| DNS | Full (Endpoint Standard tier) | Full | Limited |
| Cross-process events | Full | Limited | Limited |
| ScriptBlock content (PowerShell) | Full | Limited | n/a |

**Tier matters**: Endpoint Standard (NGAV-only) is **not** the same SKU as Enterprise EDR. Detection content requiring process-tree depth or behavioural data needs Enterprise EDR licensing on the host.

---

## 6. NGAV alerts vs EDR detections

Two separate alert categories on the same sensor:

| Source | Alert type | Notes |
|---|---|---|
| **NGAV** (Predictive Cloud Engine) | TTP / Carbon Black Reputation / Malware | Sensor-side prevention/detection |
| **Watchlist** | Custom or subscribed Report hit | Cloud-side analysis |
| **CB Threat Intel feeds** | Vendor / CB-curated IOC matches | Hash, IP, domain |

Custom detection content lives in Watchlists. NGAV behavioural rules are vendor-managed.

---

## 7. Alert override / interrupt

CBC supports **override** rules for known-good behaviour:

| Override type | Scope |
|---|---|
| Hash override | Allow a specific SHA256 |
| Path override | Allow a specific binary path |
| Cert override | Allow a specific signer |
| IT tool override | Sanction enterprise tools that trigger NGAV |

Author detection content with awareness of overrides — a generic ransomware detection that hits because of a backup tool will be silenced via override rather than tuned in the rule. Document expected override patterns in the Report description.

---

## 8. Live Response

Constrained sensor-side shell. Commands include:

| Category | Examples |
|---|---|
| **Read-only** | `ps`, `dir`, `cat`, `reg query`, `netstat` |
| **Investigative** | `memdump`, `get`, `kill` |
| **State-changing** | `put`, `rm`, `delete`, `execfg` |

Same authoring discipline as CrowdStrike RTR: read-only first, document intent before automation, no embedded secrets.

---

## 9. SIEM ingestion patterns

> Table/index names are SIEM-specific. Consult your SIEM's CBC integration documentation for exact configurations.

| CBC source | Telemetry type | Ingestion method | Notes |
|---|---|---|---|
| Alerts | Detection alerts (watchlist hits, NGAV, threat intel) | Data Forwarder → S3/Azure Blob → SIEM, or API polling | Primary alert source |
| Process events | Process creation, command-line, parent chain | Data Forwarder → S3/Azure Blob → SIEM | Requires Enterprise EDR |
| Network events | Connection metadata | Data Forwarder → S3/Azure Blob → SIEM | Requires Enterprise EDR |
| File/registry events | File and registry modifications | Data Forwarder → S3/Azure Blob → SIEM | Requires Enterprise EDR |
| Audit logs | Admin actions, policy changes | Audit Log API → SIEM | Always available |

### Data Forwarder

CBC's Data Forwarder exports event data to AWS S3 or Azure Blob Storage in JSON format. The SIEM then ingests from the storage bucket. This is the recommended method for bulk event ingestion — API polling has rate limits.

---

## 10. Entity identifier alignment

| Concept | CBC | Microsoft Defender | Sentinel | CrowdStrike |
|---|---|---|---|---|
| Host | `device_id`, `device_name` | `DeviceId`, `DeviceName` | `Computer` | `aid`, `ComputerName` |
| User | `process_username` | `AccountName`, `AccountUpn` | `UserPrincipalName` | `UserName` |
| Process | `process_guid` (stable) | `ProcessUniqueId` | n/a | `ContextProcessId_decimal` |
| Hash | `process_hash` (SHA256/MD5) | `SHA256` | `FileHash` | `SHA256HashData` |

`process_guid` is CBC's stable per-process identifier — use it for chain correlation, not PIDs.

---

## 11. Mapping into opentide MDR

When CBC content lives in `configurations.carbon_black_cloud`:

- **Identify the surface** (Watchlist Report / Scheduled Search / API IOC) in the configuration block.
- **Watchlist Report metadata** (title, description, severity, MITRE tags) populated; the MDR `description` mirrors / extends with operational context.
- **Sensor tier requirement** declared (Endpoint Standard vs Enterprise EDR) so reviewers can assess fitness.
- Coordinate with `opentide-rule` for placement and `detection-engineering` for lifecycle.

---

## 12. Worked detection patterns

### LSASS credential dumping

```
process_name:rundll32.exe AND process_cmdline:*comsvcs* AND process_cmdline:*MiniDump*
```

Watchlist Report: Severity 8, MITRE T1003.001. FP: legitimate crash dump tools — check `parent_name` for expected dump utilities.

### Encoded PowerShell execution

```
process_name:powershell.exe AND process_cmdline:*-EncodedCommand*
    AND -parent_name:ccmexec.exe
```

Watchlist Report: Severity 6, MITRE T1059.001. FP: SCCM/ConfigMgr deployments use `-EncodedCommand` legitimately — exclude `ccmexec.exe` parent.

### Suspicious service installation (PsExec pattern)

```
device_os:WINDOWS AND process_name:psexesvc.exe
```

Watchlist Report: Severity 7, MITRE T1569.002. FP: legitimate admin use of PsExec — correlate with `process_username` and time of day.

### Scheduled task persistence

```
process_name:schtasks.exe AND process_cmdline:*/create* AND process_cmdline:*AppData*
```

Watchlist Report: Severity 5, MITRE T1053.005. FP: some legitimate software creates tasks in AppData — check `process_effective_reputation`.

### Accessibility feature hijack (renamed binary)

```
((!process_name:sethc.exe AND process_original_filename:sethc.exe)
  OR (!process_name:utilman.exe AND process_original_filename:utilman.exe)
  OR (!process_name:osk.exe AND process_original_filename:osk.exe)
  OR (!process_name:Magnify.exe AND process_original_filename:Magnify.exe)
  OR (!process_name:Narrator.exe AND process_original_filename:Narrator.exe))
-enriched:true
```

Watchlist Report: Severity 8, MITRE T1546.008. FP: very rare — accessibility features should not be renamed.

### Archive extraction from email/download path

```
process_name:7zFM.exe AND
  (process_cmdline:*.iso OR process_cmdline:*.img OR process_cmdline:*.dmg) AND
  (process_cmdline:*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\Content.Outlook\\*
   OR process_cmdline:*\\Downloads\\*)
-enriched:true
```

Watchlist Report: Severity 5, MITRE T1204.002. FP: legitimate archive extraction — check file reputation and source.

### Outbound connection to rare port

```
device_os:WINDOWS AND netconn_action:ACTION_CONNECTION_CREATE
    AND netconn_remote_port:4444
    AND -netconn_remote_ipv4:10.0.0.0/8
    AND -netconn_remote_ipv4:172.16.0.0/12
    AND -netconn_remote_ipv4:192.168.0.0/16
```

Scheduled Search: common Metasploit/Meterpreter default port. Adjust port list per threat intel.

---

## 13. Quality checklist

- [ ] Surface identified (Watchlist Report / Scheduled Search / IOC).
- [ ] One TTP per Report.
- [ ] Severity calibrated (8–10 for paging-worthy, 5–7 for behavioural, 1–4 for informational).
- [ ] MITRE mapping in Report metadata + MDR description.
- [ ] Process correlation via `process_guid`, not PID.
- [ ] Sensor tier requirement declared (Endpoint Standard vs Enterprise EDR).
- [ ] `-enriched:true` appended to watchlist IOC queries to avoid duplicate hits.
- [ ] `process_original_filename` used alongside `process_name` for renamed binary detection.
- [ ] Event count thresholds used where appropriate (`netconn_count:[1 TO *]`).
- [ ] Override patterns documented in Report description.
- [ ] FP triage steps in description.
- [ ] Live Response scripts reviewed before automation.
- [ ] SIEM ingestion method documented (Data Forwarder vs API polling).
- [ ] Reputation filtering considered (`process_effective_reputation:NOT_LISTED`).
