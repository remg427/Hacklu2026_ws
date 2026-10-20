# Falcon Query Language (FQL) — Field Reference

Field names for Falcon Insight Event Search. FQL fields are case-sensitive. Always verify against your tenant's schema — fields evolve between sensor versions.

> **Rule**: Never fabricate FQL field names. If a field is not listed here, verify it in the Falcon console Event Search schema browser before using it.

---

## Event type selection

Every FQL query should start with `event_simpleName=` to select the event type.

| `event_simpleName` | Description | Detection use |
|---|---|---|
| `ProcessRollup2` | Process creation (primary) | Command-line detection, process chain analysis |
| `SyntheticProcessRollup2` | Synthetic process event | Supplementary process data |
| `DnsRequest` | DNS query | C2 domain resolution, DGA detection |
| `NetworkConnectIP4` | IPv4 network connection | Outbound C2, lateral movement |
| `NetworkConnectIP6` | IPv6 network connection | Same as above, IPv6 |
| `NetworkReceiveAcceptIP4` | Inbound connection accepted | Reverse shell, bind shell |
| `FileWritten` | File write | Payload drops, staging |
| `NewExecutableWritten` | New executable written to disk | Dropper activity |
| `ExecutableDeleted` | Executable deleted | Anti-forensics |
| `AsepValueUpdate` | Auto-Start Extensibility Point change | Persistence (Run keys, services, scheduled tasks) |
| `RegGenericValueUpdate` | Registry value modification | Persistence, configuration changes |
| `UserLogon` | User logon event | Lateral movement, authentication |
| `UserLogoff` | User logoff | Session duration |
| `UserLogonFailed` | Failed logon | Brute force, password spray |
| `UserLogonFailed2` | Failed logon (extended) | Additional failure context |
| `UserAccountCreated` | Account creation | Persistence, backdoor accounts |
| `UserAccountDeleted` | Account deletion | Anti-forensics |
| `ServiceStarted` | Service started | Persistence, lateral movement |
| `DriverLoad` | Driver loaded | BYOVD, rootkit |
| `ImageHash` | Image hash event | File reputation |
| `ModuleLoad` | Module/DLL loaded | DLL side-loading, injection |
| `ScriptControlScanTelemetry` | Script execution telemetry | PowerShell, VBScript, JScript |
| `NamedPipeCreated` | Named pipe created | C2 (Cobalt Strike, Metasploit) |
| `NamedPipeConnected` | Named pipe connected | Lateral movement via named pipes |
| `SuspiciousDnsRequest` | Suspicious DNS flagged by sensor | Sensor-side DNS anomaly |
| `ClassifiedModuleLoad` | Classified module load | Sensor-classified suspicious DLL |
| `CriticalEnvironmentVariableChanged` | Environment variable changed | PATH hijacking, persistence |

---

## Common fields (cross-event)

### Host and agent

| Field | Type | Description |
|---|---|---|
| `aid` | UUID | Agent ID — primary per-host identifier. Stable across reboots. |
| `ComputerName` | string | Hostname. May change; prefer `aid` for correlation. |
| `MachineDomain` | string | AD domain of the host. |
| `SiteName` | string | AD site name. |
| `LocalAddressIP4` | string | Host's local IPv4 address. |
| `aip` | string | Agent's external IP (as seen by the cloud). |
| `event_platform` | string | `Win`, `Mac`, `Lin`. |
| `ConfigBuild` | string | Sensor version/build. |
| `AgentVersion` | string | Sensor version string. |

### Time

| Field | Type | Description |
|---|---|---|
| `timestamp` | epoch | Event timestamp (UTC, milliseconds). |
| `ContextTimeStamp` | epoch | Process context timestamp. |
| `_time` | epoch | Splunk-style time field (Event Search). |

### Process fields (ProcessRollup2 and related)

| Field | Type | Description |
|---|---|---|
| `TargetProcessId` | decimal | OS-level PID. **Recycles — do not use for correlation.** |
| `ContextProcessId_decimal` | decimal | Falcon's stable per-process identifier. **Use this for chain correlation.** |
| `ParentProcessId_decimal` | decimal | Parent's Falcon process ID. |
| `RawProcessId` | decimal | Raw OS PID. |
| `ImageFileName` | string | Full path of the executable. |
| `FileName` | string | Executable name only (no path). |
| `CommandLine` | string | Full command line. |
| `CommandHistory` | string | Command history (shells). |
| `SHA256HashData` | string | SHA256 of the executable. |
| `MD5HashData` | string | MD5 of the executable. |
| `SHA1HashData` | string | SHA1 of the executable. |
| `UserName` | string | User who ran the process. |
| `UserSid` | string | User SID. |
| `IntegrityLevel` | string | Process integrity level. |
| `TokenType` | string | Token type (Primary, Impersonation). |
| `SessionId` | decimal | Logon session ID. |
| `ParentBaseFileName` | string | Parent process name. |
| `ParentCommandLine` | string | Parent command line (when available). |
| `GrandparentBaseFileName` | string | Grandparent process name (when available). |
| `GrandparentCommandLine` | string | Grandparent command line (when available). |

### Network fields (NetworkConnectIP4 and related)

| Field | Type | Description |
|---|---|---|
| `RemoteAddressIP4` | string | Remote IPv4 address. |
| `RemoteAddressIP6` | string | Remote IPv6 address. |
| `RemotePort` | decimal | Remote port. |
| `LocalAddressIP4` | string | Local IPv4 address. |
| `LocalPort` | decimal | Local port. |
| `ConnectionDirection` | decimal | 0 = outbound, 1 = inbound. |
| `Protocol` | decimal | IP protocol number (6 = TCP, 17 = UDP). |

### DNS fields (DnsRequest)

| Field | Type | Description |
|---|---|---|
| `DomainName` | string | Queried domain name. |
| `RequestType` | string | DNS query type (A, AAAA, CNAME, MX, TXT, etc.). |
| `ResponseIP` | string | Resolved IP address. |

### File fields (FileWritten, NewExecutableWritten)

| Field | Type | Description |
|---|---|---|
| `TargetFileName` | string | Full path of the written file. |
| `TargetDirectoryName` | string | Directory of the written file. |
| `SHA256HashData` | string | Hash of the written file. |
| `Size` | decimal | File size in bytes. |

### Registry fields (AsepValueUpdate, RegGenericValueUpdate)

| Field | Type | Description |
|---|---|---|
| `RegObjectName` | string | Registry key path. |
| `RegValueName` | string | Registry value name. |
| `RegStringValue` | string | Registry value data (string). |
| `RegNumericValue` | decimal | Registry value data (numeric). |

### Authentication fields (UserLogon, UserLogonFailed)

| Field | Type | Description |
|---|---|---|
| `UserName` | string | Account name. |
| `UserSid` | string | Account SID. |
| `LogonType` | decimal | Windows logon type (2, 3, 10, etc.). |
| `RemoteAddressIP4` | string | Source IP for network logons. |
| `AuthenticationPackage` | string | NTLM, Kerberos, Negotiate. |
| `LogonDomain` | string | Domain of the authenticating account. |

---

## NG-SIEM (LogScale / CQL) field differences

CQL queries against NG-SIEM use a different field namespace. Key differences:

| Concept | FQL (Event Search) | CQL (NG-SIEM) |
|---|---|---|
| Repository | Implicit | `#repo=falcon_data` (required) |
| Event type | `event_simpleName=` | `event_simpleName=` (same) |
| Agent ID | `aid` | `aid` (same) |
| Hostname | `ComputerName` | `ComputerName` (same) |
| Aggregation | `\| stats count by X` | `\| groupBy(X, function=count())` |
| Multi-value | `\| table X, Y` | `\| select(X, Y)` |
| Time chart | `\| timechart span=1h count` | `\| timeChart(span=1h, function=count())` |

**Rule**: Do not mix FQL and CQL syntax. Confirm which surface the query targets before authoring.

---

## Custom IOA field names

Custom IOA rules use a **different field namespace** from Event Search. Key fields in the IOA rule builder:

| IOA field | Equivalent FQL field | Notes |
|---|---|---|
| Image File Name | `ImageFileName` | Supports wildcards |
| Command Line | `CommandLine` | Supports wildcards and regex |
| Parent Image File Name | `ParentBaseFileName` | Parent process |
| File Path | `TargetFileName` | For file-based IOAs |
| Registry Key | `RegObjectName` | For registry-based IOAs |
| Remote IP | `RemoteAddressIP4` | For network-based IOAs |
| Remote Port | `RemotePort` | For network-based IOAs |

IOA conditions are built in the UI — they are not raw FQL. The field names map to FQL equivalents but the syntax is condition-tree based, not query-string based.
