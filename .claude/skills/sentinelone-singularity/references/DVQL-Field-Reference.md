# Deep Visibility Query Language (DVQL) — Field Reference

Field names for SentinelOne Deep Visibility event search. DVQL fields use dot-notation namespaces. Always verify against your console's schema — fields evolve between agent versions.

> **Rule**: Never fabricate DVQL field names. If a field is not listed here, verify it in the SentinelOne console Deep Visibility query builder before using it.

---

## Event type selection

DVQL queries can filter by `EventType` or by field presence. Common event types:

| EventType | Description | Detection use |
|---|---|---|
| `Process Creation` | Process started | Command-line detection, process chain |
| `Process Termination` | Process ended | Short-lived process analysis |
| `File Creation` | File written to disk | Payload drops, staging |
| `File Modification` | File modified | Tampering, config changes |
| `File Deletion` | File deleted | Anti-forensics |
| `File Rename` | File renamed | Masquerading |
| `Registry Key Creation` | Registry key created | Persistence |
| `Registry Value Modified` | Registry value changed | Persistence, configuration |
| `DNS Resolved` | DNS query resolved | C2 domain resolution |
| `DNS Unresolved` | DNS query failed | DGA, dead C2 |
| `IP Connect` | Outbound network connection | C2, lateral movement |
| `IP Listen` | Listening socket opened | Reverse shell, bind shell |
| `Login` | User logon | Lateral movement |
| `Logout` | User logoff | Session analysis |
| `Module Load` | DLL/module loaded | DLL side-loading, injection |
| `Named Pipe Creation` | Named pipe created | C2 (Cobalt Strike) |
| `Named Pipe Connection` | Named pipe connected | Lateral movement |
| `Task Register` | Scheduled task created | Persistence |
| `Task Update` | Scheduled task modified | Persistence modification |
| `Task Start` | Scheduled task executed | Persistence trigger |
| `Indicator` | Threat indicator matched | Sensor-side detection |
| `Command Script` | Script execution | PowerShell, cmd, bash |

---

## Process fields

| Field | Type | Description |
|---|---|---|
| `process.name` | string | Process executable name |
| `process.image.path` | string | Full path of the executable |
| `process.command_line` | string | Full command line |
| `process.pid` | integer | OS-level PID. **Recycles — use `storyline.id` for correlation.** |
| `process.storyline.id` | UUID | **Stable per-process causal chain identifier. Primary correlation key.** |
| `process.parent.name` | string | Parent process name |
| `process.parent.image.path` | string | Parent process full path |
| `process.parent.command_line` | string | Parent command line |
| `process.parent.storyline.id` | UUID | Parent's Storyline ID |
| `process.parent.pid` | integer | Parent OS PID |
| `process.image.sha256` | string | SHA256 hash of the executable |
| `process.image.sha1` | string | SHA1 hash |
| `process.image.md5` | string | MD5 hash |
| `process.user.name` | string | User who ran the process |
| `process.user.sid` | string | User SID (Windows) |
| `process.integrity_level` | string | Process integrity level |
| `process.start_time` | datetime | Process start timestamp |
| `process.is_redirect_cmd_processor` | boolean | cmd.exe spawned by another process |
| `process.is_storyline_root` | boolean | Root of the Storyline (initial process) |

---

## Endpoint fields

| Field | Type | Description |
|---|---|---|
| `endpoint.name` | string | Hostname |
| `endpoint.os` | string | `windows`, `macos`, `linux` |
| `endpoint.ip` | string | Endpoint IP address |
| `agent.uuid` | UUID | Agent identifier — stable per-endpoint |
| `agent.version` | string | Agent version |
| `site.name` | string | SentinelOne site name |
| `group.name` | string | SentinelOne group name |

---

## Network fields

| Field | Type | Description |
|---|---|---|
| `dst.ip.address` | string | Destination IP |
| `dst.port.number` | integer | Destination port |
| `src.ip.address` | string | Source IP |
| `src.port.number` | integer | Source port |
| `network.direction` | string | `OUTGOING`, `INCOMING` |
| `network.protocol` | string | `TCP`, `UDP` |

---

## DNS fields

| Field | Type | Description |
|---|---|---|
| `dns.request` | string | Queried domain name |
| `dns.response` | string | Resolved IP address |

---

## File fields

| Field | Type | Description |
|---|---|---|
| `tgt.file.path` | string | Target file full path |
| `tgt.file.name` | string | Target file name |
| `tgt.file.extension` | string | File extension |
| `tgt.file.sha256` | string | SHA256 of the file |
| `tgt.file.sha1` | string | SHA1 of the file |
| `tgt.file.md5` | string | MD5 of the file |
| `tgt.file.size` | integer | File size in bytes |
| `tgt.file.is_signed` | boolean | Whether the file is signed |
| `tgt.file.signer_identity` | string | Code signing identity |

---

## Registry fields

| Field | Type | Description |
|---|---|---|
| `registry.key_path` | string | Full registry key path |
| `registry.value_name` | string | Registry value name |
| `registry.value_data` | string | Registry value data |
| `registry.value_type` | string | Value type (REG_SZ, REG_DWORD, etc.) |

---

## Module fields

| Field | Type | Description |
|---|---|---|
| `module.path` | string | Loaded module full path |
| `module.sha256` | string | Module SHA256 hash |
| `module.size` | integer | Module size |

---

## DVQL operators

| Operator | Syntax | Notes |
|---|---|---|
| Equality | `field Is "value"` | Case-sensitive |
| Inequality | `field IsNot "value"` | |
| Contains | `field Contains "value"` | Case-sensitive substring |
| Contains (case-insensitive) | `field ContainsCIS "value"` | Preferred for command lines |
| Starts with | `field StartsWith "value"` | |
| Ends with | `field EndsWith "value"` | |
| Regex | `field Matches "pattern"` | Full regex support |
| In (multi-value) | `field In Contains ("a", "b")` | Multi-value membership |
| In (case-insensitive) | `field In Contains Anycase ("a", "b")` | |
| Boolean | `AND`, `OR`, `NOT` | Always parenthesise mixed `AND`/`OR` |

---

## PowerQuery (SDL) field differences

PowerQuery in the Singularity Data Lake uses a **different field namespace** from DVQL. Key differences:

| Concept | DVQL | PowerQuery |
|---|---|---|
| Process name | `process.name` | Field names vary by ingested source |
| Filtering | `field Is "value"` | `field == "value"` or `field contains "value"` |
| Aggregation | Not supported in DVQL | `\| group count() by field` |
| Pipeline | Not supported | `\| parse`, `\| let`, `\| filter`, `\| join` |

**Rule**: Do not mix DVQL and PowerQuery syntax. DVQL is for Deep Visibility (endpoint telemetry). PowerQuery is for Singularity Data Lake (multi-source analytics).

---

## Cross-platform entity alignment

| Concept | SentinelOne | Microsoft Defender | CrowdStrike |
|---|---|---|---|
| Host | `agent.uuid`, `endpoint.name` | `DeviceId`, `DeviceName` | `aid`, `ComputerName` |
| User | `process.user.name` | `AccountName`, `AccountUpn` | `UserName` |
| Process correlation | `process.storyline.id` | `ProcessUniqueId` | `ContextProcessId_decimal` |
| Hash | `process.image.sha256` | `SHA256` | `SHA256HashData` |
| Network | `dst.ip.address` | `RemoteIP` | `RemoteAddressIP4` |
