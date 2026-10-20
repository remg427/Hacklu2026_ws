# Defender Multi-Query Correlation Patterns

Worked correlation queries for Microsoft Defender for Endpoint Advanced Hunting. Each pattern is a complete, runnable KQL block. Column names still defer to the tenant schema reference — see the column-authority rule in `SKILL.md`.

## Pattern 1 — Sequential: process → network

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "-enc"
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where ActionType == "ConnectionSuccess"
) on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| project Timestamp, DeviceName, ProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
```

## Pattern 2 — Temporal correlation (file → process within N min)

```kql
let file_events =
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType == "FileCreated"
    | where FileName endswith ".exe"
    | where FolderPath has "Temp"
    | project FileTimestamp = Timestamp, DeviceId, FileName, FolderPath;
let process_events =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | project ProcessTimestamp = Timestamp, DeviceId, FileName, ProcessCommandLine;
file_events
| join kind=inner process_events on DeviceId, FileName
| where ProcessTimestamp between (FileTimestamp .. (FileTimestamp + 5m))
```

> Use `ProcessUniqueId` / `InitiatingProcessUniqueId` rather than recycled PIDs when joining on processes. Windows reuses PIDs; without temporal validation, joins match unrelated events.

## Pattern 3 — Statistical anomaly (outbound volume)

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (443, 80, 8080)
| summarize
    BytesSent = sum(SentBytes),
    ConnectionCount = count(),
    UniqueDestinations = dcount(RemoteIP)
    by DeviceName, bin(Timestamp, 1h)
| where BytesSent > 100000000  // > 100 MB/h — adjust per baseline
| order by BytesSent desc
```

## Pattern 4 — Beaconing detection

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| summarize
    ConnectionTimes = make_list(Timestamp),
    ConnectionCount = count()
    by DeviceName, RemoteIP, InitiatingProcessFileName
| where ConnectionCount > 20
| extend Intervals = array_sort_asc(ConnectionTimes)
| mv-apply Intervals on (
    extend PrevTime = prev(Intervals, 1)
    | where isnotempty(PrevTime)
    | extend IntervalSeconds = datetime_diff('second', Intervals, PrevTime)
    | summarize AvgInterval = avg(IntervalSeconds), StdevInterval = stdev(IntervalSeconds)
)
| where StdevInterval / AvgInterval < 0.2  // low CV = consistent timing = beaconing
```

## Pattern 5 — Prevalence-based hunting (rare binaries)

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| invoke FileProfile(SHA1, 1000)
| where GlobalPrevalence < 100 or isempty(GlobalPrevalence)  // include enrichment gaps
| where not(IsRootSignerMicrosoft == true)
| project Timestamp, DeviceName, FileName, FolderPath, SHA1,
    GlobalPrevalence, GlobalFirstSeen, Signer, IsTrusted,
    InitiatingProcessFileName, AccountName
| order by GlobalPrevalence asc
```

**`FileProfile()` gating thresholds**:

| Filter | Use case |
|---|---|
| `GlobalPrevalence < 200` | Suspicious, investigate |
| `GlobalPrevalence < 500 and not(IsTrusted)` | Unsigned low-prevalence, flag |
| `GlobalPrevalence < 100 and not(IsRootSignerMicrosoft)` | Rare non-Microsoft binary, high priority |

Always combine with the second parameter `1000` (lookup window in records). Always handle `isempty(GlobalPrevalence)` — new files, internal-only binaries, and isolated-network binaries have no enrichment.

## Pattern 6 — Baseline deviation (autorun set comparison)

```kql
let baseline_entries = toscalar(
    DeviceRegistryEvents
    | where Timestamp between (ago(37d) .. ago(7d))
    | where RegistryKey has @"\CurrentVersion\Run"
    | summarize make_set(RegistryValueData)
);
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has @"\CurrentVersion\Run"
| where ActionType == "RegistryValueSet"
| where not(RegistryValueData in (baseline_entries))
| project Timestamp, DeviceName, RegistryKey, RegistryValueName,
    RegistryValueData, InitiatingProcessFileName, AccountName
```

## Pattern 7 — Process chain reconstruction

```kql
let target_device = "<DeviceName>";
let incident_time = datetime(<timestamp>);
DeviceProcessEvents
| where Timestamp between ((incident_time - 2h) .. (incident_time + 2h))
| where DeviceName == target_device
| order by Timestamp asc
| extend ProcessSequence = row_cumsum(1)
| extend TimeSincePrev = datetime_diff('second', Timestamp, prev(Timestamp, 1))
| extend IsRapidExecution = iff(TimeSincePrev < 2, true, false)
| project Timestamp, ProcessSequence, TimeSincePrev, IsRapidExecution,
    FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
```

## Pattern 8 — Multi-stage with `materialize()`

```kql
let lookback = ago(7d);
let email_attachments = materialize(
    DeviceFileEvents
    | where Timestamp > lookback
    | where InitiatingProcessFileName in~ ("outlook.exe", "msedge.exe", "chrome.exe")
    | where FileName endswith_cs ".exe" or FileName endswith_cs ".dll" or FileName endswith_cs ".hta"
    | project AttachTime = Timestamp, DeviceId, DeviceName, FileName, FolderPath, SHA256
);
let executions = materialize(
    email_attachments
    | join kind=inner (
        DeviceProcessEvents | where Timestamp > lookback
    ) on DeviceId, $left.FileName == $right.FileName
    | where Timestamp between (AttachTime .. (AttachTime + 10m))
    | project ExecTime = Timestamp, DeviceId, DeviceName, FileName, ProcessCommandLine, SHA256
);
executions
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > lookback
    | where ActionType == "ConnectionSuccess"
) on DeviceId, $left.FileName == $right.InitiatingProcessFileName
| where Timestamp between (ExecTime .. (ExecTime + 5m))
| project ExecTime, DeviceName, FileName, ProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
```

## Pattern 9 — Exclusion-based (`leftanti` chain)

```kql
let baseline = materialize(
    DeviceRegistryEvents
    | where Timestamp between (ago(37d) .. ago(7d))
    | where RegistryKey has @"\CurrentVersion\Run"
    | distinct RegistryValueName, RegistryValueData
);
let known_good = datatable(ValuePattern: string) [
    "SecurityHealth", "Windows Defender", "OneDrive", "Teams"
];
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has @"\CurrentVersion\Run"
| where ActionType == "RegistryValueSet"
| join kind=leftanti baseline on RegistryValueName, RegistryValueData
| where not(RegistryValueData has_any (known_good))
```

## Pattern 10 — DGA domain detection

```kql
// MITRE: T1568.002 (Domain Generation Algorithms)
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where isnotempty(RemoteUrl)
| extend Domain = tostring(parse_url(strcat("http://", RemoteUrl)).Host)
| where isnotempty(Domain)
| extend DomainParts = split(Domain, ".")
| extend SLD = tostring(DomainParts[array_length(DomainParts) - 2])
| where strlen(SLD) > 6
| extend ConsonantRatio = countof(SLD, "[bcdfghjklmnpqrstvwxyz]", "regex") * 1.0 / strlen(SLD)
| extend DigitRatio = countof(SLD, "[0-9]", "regex") * 1.0 / strlen(SLD)
| where (ConsonantRatio > 0.7 and strlen(SLD) > 10)
    or (DigitRatio > 0.3 and strlen(SLD) > 8)
| summarize ConnectionCount = count(), Devices = dcount(DeviceName)
    by Domain, SLD, ConsonantRatio, DigitRatio
| order by ConnectionCount desc
```

## Pattern 11 — Certificate-based supply chain hunting

```kql
// MITRE: T1553.002 (Subvert Trust Controls: Code Signing)
DeviceFileCertificateInfo
| where Timestamp > ago(30d)
| where isnotempty(Signer)
| where not(IsTrusted)
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | project Timestamp, DeviceName, FileName, FolderPath, SHA1, AccountName, ProcessCommandLine
) on SHA1
| project Timestamp, DeviceName, FileName, FolderPath, Signer, Issuer,
    CertificateCreationTime, IsTrusted, IsRootSignerMicrosoft,
    AccountName, ProcessCommandLine
```

## Pattern 12 — Multi-technique union (credential access)

```kql
// MITRE: T1003 (OS Credential Dumping, multiple sub-techniques)
let lookback = ago(14d);
let lsass_access =
    DeviceProcessEvents
    | where Timestamp > lookback
    | where FileName =~ "lsass.exe" or ProcessCommandLine has "lsass"
    | where InitiatingProcessFileName !in~ ("svchost.exe", "services.exe", "wininit.exe")
    | project Timestamp, DeviceName, Technique = "T1003.001-LSASS", AccountName,
        Detail = ProcessCommandLine;
let sam_access =
    DeviceRegistryEvents
    | where Timestamp > lookback
    | where RegistryKey has @"SYSTEM\CurrentControlSet\Control\SecurityProviders"
    | where ActionType == "RegistryValueSet"
    | project Timestamp, DeviceName, Technique = "T1003.002-SAM",
        AccountName = InitiatingProcessAccountName,
        Detail = strcat(RegistryKey, " → ", RegistryValueData);
let ntds_access =
    DeviceProcessEvents
    | where Timestamp > lookback
    | where ProcessCommandLine has_any ("ntds.dit", "ntdsutil", "vssadmin", "shadow")
    | project Timestamp, DeviceName, Technique = "T1003.003-NTDS", AccountName,
        Detail = ProcessCommandLine;
union kind=outer lsass_access, sam_access, ntds_access
| summarize Techniques = make_set(Technique), EventCount = count()
    by DeviceName, AccountName, bin(Timestamp, 1h)
| where array_length(Techniques) >= 2  // two or more credential techniques = high confidence
```

## Pattern 13 — Named pipes (C2 frameworks)

```kql
// MITRE: T1570 / T1071 (Cobalt Strike, Metasploit, custom C2)
let suspicious_pipe_patterns = dynamic([
    @"\\MSSE-", @"\\msagent_", @"\\postex_", @"\\status_",
    @"\\mojo.", @"\\chrome.", @"\\edge."
]);
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType == "NamedPipeEvent"
| extend PipeName = tostring(parse_json(AdditionalFields).PipeName)
| extend PipeAction = tostring(parse_json(AdditionalFields).NamedPipeEnd)
| where PipeName has_any (suspicious_pipe_patterns)
    or PipeName matches regex @"^\\[a-f0-9]{8}$"  // random hex pipe names
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
    InitiatingProcessCommandLine, PipeName, PipeAction
```

---
