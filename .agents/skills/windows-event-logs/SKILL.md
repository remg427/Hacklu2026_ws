---
name: windows-event-logs
description: Windows native event log authoring guidance for detection engineering — Security, Sysmon, PowerShell, and system event channels. Covers critical Event IDs (4624/4625/4688/4697/4720/5140/7045), Sysmon EID 1-29 with configuration discipline, PowerShell ScriptBlock/Module logging, EVTX channel routing, audit policy prerequisites, ETW fundamentals, and SIEM ingestion patterns. Use when authoring detections that depend on native Windows telemetry, configuring audit policies for detection coverage, or bridging Windows events to platform-specific query skills.
---

# Windows Event Logs — detection authoring

This skill encodes the Windows-native event log knowledge required for detection content that depends on Security, Sysmon, PowerShell, or System event channels. It bridges the gap between raw Windows telemetry and the platform-specific query skills used by your SIEM or EDR.

---

## 1. Event channel landscape

| Channel | Log name | Key content |
|---|---|---|
| **Security** | `Security` | Authentication, process creation, object access, policy changes, account management |
| **Sysmon** | `Microsoft-Windows-Sysmon/Operational` | Process creation with hashes, network connections, file creation, registry, DNS, WMI, named pipes, clipboard |
| **PowerShell** | `Microsoft-Windows-PowerShell/Operational` | ScriptBlock logging (4104), Module logging (4103) |
| **System** | `System` | Service installation (7045), driver loads, system state |
| **Windows Defender** | `Microsoft-Windows-Windows Defender/Operational` | AV detections, exclusion changes, tamper events |
| **Task Scheduler** | `Microsoft-Windows-TaskScheduler/Operational` | Scheduled task creation/modification/execution |
| **WMI** | `Microsoft-Windows-WMI-Activity/Operational` | WMI subscription events |
| **AppLocker** | `Microsoft-Windows-AppLocker/*` | Application execution control |
| **NTLM** | `Microsoft-Windows-NTLM/Operational` | NTLM authentication events (requires audit policy) |

---

## 2. Critical Security Event IDs

### Authentication

| EID | Description | Detection use |
|---|---|---|
| **4624** | Successful logon | Lateral movement (Type 3/10), service logon (Type 5), interactive (Type 2) |
| **4625** | Failed logon | Brute force, password spray |
| **4648** | Explicit credential logon | Credential use with alternate identity (runas, PsExec) |
| **4634** / **4647** | Logoff | Session duration analysis |
| **4672** | Special privileges assigned | Privileged logon detection |
| **4768** | Kerberos TGT request | Kerberoasting (RC4 encryption type 0x17) |
| **4769** | Kerberos service ticket request | Kerberoasting, service access |
| **4771** | Kerberos pre-auth failed | Password spray against Kerberos |
| **4776** | NTLM credential validation | NTLM relay, pass-the-hash |

**Logon Type reference** (EID 4624/4625):

| Type | Name | Meaning |
|---|---|---|
| 2 | Interactive | Console logon |
| 3 | Network | SMB, WinRM, mapped drives |
| 4 | Batch | Scheduled tasks |
| 5 | Service | Service start |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | IIS basic auth, PowerShell remoting with CredSSP |
| 9 | NewCredentials | `runas /netonly` |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Cached domain credentials |

### Process creation

| EID | Description | Detection use |
|---|---|---|
| **4688** | Process creation | Command-line logging (requires audit policy + GPO) |

**Critical prerequisite**: Process command-line logging is **not enabled by default**. Requires:
- Audit Policy: `Audit Process Creation` → Success
- GPO: `Include command line in process creation events` → Enabled

Without this, EID 4688 contains the process name but **no command line** — most detection value is lost.

### Account management

| EID | Description | Detection use |
|---|---|---|
| **4720** | User account created | Persistence, backdoor accounts |
| **4722** | User account enabled | Re-enabled dormant accounts |
| **4724** | Password reset attempt | Credential manipulation |
| **4728** / **4732** / **4756** | Member added to security group | Privilege escalation |
| **4738** | User account changed | Account property manipulation |
| **4740** | Account locked out | Brute force indicator |

### Object access and file shares

| EID | Description | Detection use |
|---|---|---|
| **4663** | Object access attempt | File/registry access auditing |
| **5140** | Network share accessed | Lateral movement via SMB |
| **5145** | Network share object checked | Detailed share access (file-level) |

### Service and scheduled task

| EID | Description | Detection use |
|---|---|---|
| **7045** (System) | Service installed | Persistence, PsExec, lateral movement |
| **4697** (Security) | Service installed (Security log) | Same as 7045, different channel |
| **4698** | Scheduled task created | Persistence |
| **4702** | Scheduled task updated | Persistence modification |

### Policy and privilege

| EID | Description | Detection use |
|---|---|---|
| **4703** | Token right adjusted | Privilege escalation |
| **4719** | Audit policy changed | Defence impairment |
| **1102** | Audit log cleared | Anti-forensics |

---

## 3. Sysmon Event IDs

Sysmon provides richer telemetry than native Security events but requires deployment and configuration.

| EID | Description | Detection use |
|---|---|---|
| **1** | Process creation (with hashes, parent, command line) | Primary process detection |
| **2** | File creation time changed | Timestomping |
| **3** | Network connection | Outbound C2, lateral movement |
| **5** | Process terminated | Process lifecycle |
| **6** | Driver loaded | Rootkit, vulnerable driver (BYOVD) |
| **7** | Image loaded (DLL) | DLL side-loading, injection |
| **8** | CreateRemoteThread | Process injection |
| **9** | RawAccessRead | Direct disk access (credential theft) |
| **10** | ProcessAccess | LSASS access (credential dumping) |
| **11** | FileCreate | Payload drops, staging |
| **12/13/14** | Registry events | Persistence, configuration changes |
| **15** | FileCreateStreamHash | ADS (Alternate Data Streams) |
| **17/18** | Pipe created/connected | Named pipe C2 (Cobalt Strike, Metasploit) |
| **19/20/21** | WMI events | WMI persistence |
| **22** | DNS query | C2 domain resolution, DGA |
| **23** | FileDelete (archived) | Deleted file capture |
| **24** | Clipboard change | Clipboard monitoring |
| **25** | Process tampering | Process hollowing, herpaderping |
| **26** | FileDeleteDetected | File deletion without archive |
| **27** | FileBlockExecutable | Executable blocked |
| **28** | FileBlockShredding | Shredding blocked |
| **29** | FileExecutableDetected | Executable file detected |

### Sysmon configuration discipline

- **Never deploy default Sysmon config in production.** The default logs everything and overwhelms storage.
- Use community-maintained configs (SwiftOnSecurity, Olaf Hartong) as a **starting point**, then tune.
- **Exclude high-volume legitimate processes** via `<RuleGroup>` exclusions — but document every exclusion.
- **Hash algorithms**: configure `SHA256` minimum. `MD5` alone is insufficient for modern threat intel.
- **LSASS protection** (EID 10): filter `TargetImage` to `lsass.exe` only — unfiltered ProcessAccess is extremely noisy.

---

## 4. PowerShell logging

| Feature | Event ID | Channel | Prerequisite |
|---|---|---|---|
| **ScriptBlock logging** | 4104 | PowerShell Operational | GPO: `Turn on PowerShell Script Block Logging` |
| **Module logging** | 4103 | PowerShell Operational | GPO: `Turn on Module Logging` (specify modules) |
| **Transcription** | — | File-based | GPO: `Turn on PowerShell Transcription` |

**ScriptBlock logging (4104)** is the highest-value PowerShell telemetry. Loader names in this list are strings that show up in the logged script; this skill does not run them.
- Captures the **deobfuscated** script content (after PowerShell's own parsing)
- Captures scripts loaded via `-EncodedCommand`, `Invoke-Expression`, `Add-Type`
- Warning level 3 = suspicious (automatic for known-bad patterns)

**Detection patterns** (indicator strings to look for in 4104 script text; not commands this skill runs):
- Base64-decoded content containing `WebClient`, `DownloadString`, `IEX`
- AMSI bypass attempts (`AmsiUtils`, `amsiInitFailed`)
- Reflection-based .NET calls (`[System.Reflection.Assembly]::Load`)
- Credential access (`Get-Credential`, `ConvertTo-SecureString` with plaintext)

---

## 5. Audit policy prerequisites

Detection content must declare which audit policies are required. Without the correct policy, the events simply do not generate.

| Category | Subcategory | Required for |
|---|---|---|
| Account Logon | Credential Validation | 4776 (NTLM) |
| Account Logon | Kerberos Authentication Service | 4768, 4771 |
| Account Logon | Kerberos Service Ticket Operations | 4769 |
| Logon/Logoff | Logon | 4624, 4625 |
| Logon/Logoff | Special Logon | 4672 |
| Object Access | File Share | 5140, 5145 |
| Object Access | Detailed File Share | 5145 (file-level) |
| Detailed Tracking | Process Creation | 4688 |
| Account Management | User Account Management | 4720, 4722, 4724, 4738 |
| Account Management | Security Group Management | 4728, 4732, 4756 |
| Policy Change | Audit Policy Change | 4719 |
| System | Security System Extension | 4697 |

**Rule**: Every detection that depends on a specific Event ID must document the audit policy prerequisite. A detection for EID 5145 that doesn't mention "Detailed File Share auditing required" will silently fail in environments without it.

---

## 6. SIEM ingestion patterns

> Table/index names are SIEM-specific. Consult your SIEM's Windows event integration documentation for exact table names and field mappings.

| Windows source | Telemetry type | Ingestion method | Notes |
|---|---|---|---|
| Security log | Authentication, process, account management events | Windows Event Forwarding (WEF), SIEM agent, or EDR sensor | Primary detection source |
| Sysmon | Process, file, network, registry, DNS, pipe events | WEF or SIEM agent (Sysmon channel) | Requires Sysmon deployment + config |
| PowerShell Operational | ScriptBlock (4104), Module (4103) logging | WEF or SIEM agent | Requires GPO enablement |
| System | Service installation (7045), driver loads | WEF or SIEM agent | Always available |
| Windows Defender Operational | AV detections, exclusion changes, tamper events | WEF or SIEM agent | Always available on Windows 10+ |
| Task Scheduler Operational | Scheduled task lifecycle | WEF or SIEM agent | Always available |

### EDR sensor overlap with Sysmon

Modern EDR sensors (Defender, CrowdStrike, SentinelOne, Carbon Black, etc.) provide **native sensor telemetry** that overlaps significantly with Sysmon for process, file, and network events. In EDR-managed environments, Sysmon may be partially redundant. However, Sysmon provides unique value for:
- **Named pipe events** (EID 17/18) — limited or no EDR equivalent
- **WMI subscription events** (EID 19/20/21) — partial EDR coverage
- **Clipboard monitoring** (EID 24) — no EDR equivalent
- **DNS query logging** (EID 22) — EDR coverage varies in granularity
- **File creation time changes** (EID 2) — timestomping detection

---

## 7. Event data structure

Windows events store structured data in XML format within the `EventData` or `UserData` element. Key extraction considerations:

### Common EventData fields by EID

| EID | Key fields | Notes |
|---|---|---|
| 4624 | `TargetUserName`, `TargetDomainName`, `LogonType`, `IpAddress`, `IpPort`, `WorkstationName` | Logon Type is critical for filtering |
| 4625 | `TargetUserName`, `LogonType`, `FailureReason`, `Status`, `SubStatus`, `IpAddress` | Status/SubStatus codes identify failure reason |
| 4688 | `NewProcessName`, `CommandLine`, `ParentProcessName`, `TokenElevationType` | CommandLine requires GPO enablement |
| 4720 | `TargetUserName`, `TargetDomainName`, `SubjectUserName` | Who created which account |
| 7045 | `ServiceName`, `ImagePath`, `ServiceType`, `StartType`, `AccountName` | Service binary path is key detection field |
| 4104 | `ScriptBlockText`, `ScriptBlockId`, `Path` | Deobfuscated script content |

### Extraction guidance

- **Prefer pre-parsed fields** when your SIEM provides them — XML parsing is expensive at query time.
- **Fall back to XML extraction** only when the SIEM does not pre-parse the needed field.
- **Field positions in XML are not guaranteed** across Windows versions — extract by field name, not array index.
- Consult your SIEM's documentation for which EventData fields are pre-parsed into dedicated columns.

---

## 8. ETW (Event Tracing for Windows) fundamentals

ETW is the underlying mechanism that generates all Windows events. Understanding ETW is relevant for advanced detection and evasion awareness.

### How events flow

```
Application / kernel → ETW Provider → ETW Session → Event Log channel → EVTX file → SIEM
```

### Detection-relevant ETW concepts

| Concept | Relevance |
|---|---|
| **ETW providers** | Each event source registers as a provider (e.g., `Microsoft-Windows-Security-Auditing`). Attackers may attempt to disable or patch providers. |
| **ETW patching** | Attackers can patch `ntdll!EtwEventWrite` in-process to blind ETW-based telemetry (including AMSI). Detection: monitor for `ntdll.dll` memory modifications. |
| **ETW session limits** | Windows has a maximum of 64 concurrent ETW sessions. Exhausting sessions can blind security tools. |
| **Provider GUIDs** | Each provider has a GUID. Sysmon's provider GUID is well-known — attackers may specifically target it. |
| **Kernel-mode ETW** | Some events (e.g., process creation, image loads) originate from kernel-mode providers and are harder to tamper with from user-mode. |

### Defence impairment via ETW

| Attack | Detection signal |
|---|---|
| ETW provider patching | Sysmon EID 10 (ProcessAccess to `ntdll.dll`), or EDR-specific tamper alerts |
| Audit log cleared | Security EID 1102 |
| Audit policy changed | Security EID 4719 |
| Sysmon service stopped | System EID 7036 (Sysmon service state change) |
| Event log service stopped | System EID 7036 (EventLog service state change) |

---

## 9. Windows Defender Operational events

| EID | Description | Detection use |
|---|---|---|
| **1116** | Malware detected | AV detection — correlate with process context |
| **1117** | Action taken on malware | AV remediation action |
| **5001** | Real-time protection disabled | Defence impairment |
| **5007** | Configuration changed | Exclusion added, settings weakened |
| **5010** | Scanning disabled | Defence impairment |
| **1121** | ASR rule triggered (block mode) | Attack Surface Reduction detection |
| **1122** | ASR rule triggered (audit mode) | ASR detection in audit mode |

**Key detection**: EID 5007 with exclusion path additions is a common attacker technique to blind Defender before deploying payloads. Monitor for exclusion changes targeting sensitive paths (`C:\Windows\Temp`, `C:\Users\*\AppData`, etc.).

---

## 10. Detection anti-patterns

| Anti-pattern | Description | Fix |
|---|---|---|
| **Assuming command-line logging is enabled** | Writing 4688 detections without noting the GPO prerequisite | Document the prerequisite; provide a validation query |
| **Sysmon without config declaration** | Referencing Sysmon EIDs without specifying which config rules must be active | Declare required Sysmon config rules |
| **Logon Type confusion** | Alerting on all 4624 events without filtering by Logon Type | Filter to relevant types (3, 10 for lateral movement) |
| **Machine account noise** | Not excluding `$`-suffixed accounts from authentication detections | Filter out accounts ending in `$` (machine accounts) |
| **Service account noise** | Not excluding known service accounts from logon anomaly detections | Maintain exclusion list with audit trail |
| **EID 4688 without parent process** | Missing the parent process context that Sysmon EID 1 provides natively | Use Sysmon EID 1 or EDR process creation telemetry for parent chain |

---

## 11. Quality checklist

- [ ] Audit policy prerequisites documented for every Event ID used.
- [ ] Sysmon configuration requirements declared (if Sysmon EIDs referenced).
- [ ] PowerShell logging GPO requirements declared (if 4103/4104 referenced).
- [ ] Logon Type filtered appropriately for authentication detections.
- [ ] Machine accounts (`$`) excluded where appropriate.
- [ ] SIEM ingestion method documented (WEF, agent, EDR sensor).
- [ ] Command-line logging prerequisite noted for EID 4688 detections.
- [ ] Pre-parsed fields preferred over XML extraction at query time.
- [ ] Sysmon vs EDR native telemetry overlap considered for the target environment.
- [ ] MITRE ATT&CK data components aligned with the event source.
- [ ] Defence impairment events monitored: EID 1102 (log cleared), 4719 (audit policy changed), Sysmon/EventLog service stops.
- [ ] Windows Defender exclusion changes (EID 5007) monitored.
- [ ] ETW tampering awareness documented for advanced evasion scenarios.
- [ ] EventData field extraction uses field names, not array indices.
---

## 12. Reference catalogues

- `references/Audit-Policy-Matrix.md` — Comprehensive EID-to-audit-policy mapping, Sysmon config requirements, PowerShell GPO paths, and minimum audit policy sets per detection goal.
