---
name: windows-internals
description: Windows operating system internals relevant for detection engineering — process creation chain (CreateProcess to token assignment), access token and privilege model (SeDebugPrivilege, integrity levels, UAC), DLL loading order and hijacking surface, service control manager architecture, COM/DCOM/WMI execution model, named pipe IPC, ETW provider landscape, AMSI architecture, registry hive structure, and the mapping between OS-level operations and the telemetry they produce. Use when authoring detections that need to understand WHY a behaviour is suspicious at the OS level, not just WHAT tool produces it.
---

# Windows Internals — detection-relevant knowledge

This skill encodes how Windows actually works at the level needed to write detections that survive tool changes and evasion. It answers: "Why is this behaviour suspicious?" rather than "What tool name should I look for?"

---

## 1. Process creation chain

When a process is created on Windows, the following sequence occurs:

```
CreateProcess(W) API call
  → Kernel validates executable image
  → Access token assigned (inherited from parent or explicitly specified)
  → Primary thread created
  → DLLs loaded (ntdll.dll → kernel32.dll → application imports)
  → Process initialisation (TLS callbacks, DllMain for loaded DLLs)
  → Entry point executed
```

### Detection-relevant implications

| Concept | Why it matters for detection |
|---|---|
| **Parent-child relationship** | Every process has a parent. Anomalous parent-child pairs (e.g. `excel.exe` → `powershell.exe`) are high-signal. |
| **Token inheritance** | Child processes inherit the parent's access token by default. `runas /netonly` creates a new logon session with different network credentials — the process appears to run as the local user but authenticates to the network as someone else (Logon Type 9). |
| **Command-line logging** | The command line is set at creation time and cannot be changed after. However, `ProcessCommandLine` can be spoofed via `NtQueryInformationProcess` manipulation before the process starts executing — Sysmon EID 1 captures the original, not the spoofed version. |
| **PID recycling** | Windows reuses PIDs. A PID from January may be reused in February. Never correlate on PID alone — use `ProcessUniqueId` (Defender), `ContextProcessId_decimal` (CrowdStrike), `process.storyline.id` (SentinelOne), or `process_guid` (Sysmon/CBC). |
| **Process hollowing** | `CreateProcess` with `CREATE_SUSPENDED` → unmap original image → map malicious image → resume. The process appears legitimate by name but executes different code. Sysmon EID 25 (Process Tampering) detects this. |

---

## 2. Access tokens and privileges

Every process runs with an **access token** that determines what it can do.

### Token components

| Component | Description | Detection relevance |
|---|---|---|
| **User SID** | Identity of the user | Account attribution |
| **Group SIDs** | Group memberships | Privilege group membership (Domain Admins, Administrators) |
| **Privileges** | Specific capabilities | `SeDebugPrivilege` = can open any process; `SeImpersonatePrivilege` = can impersonate tokens |
| **Integrity level** | Untrusted → Low → Medium → High → System | Determines what objects the process can access |
| **Logon session** | Links to the authentication event | Correlates process activity to authentication |

### Critical privileges for detection

| Privilege | What it enables | Why attackers want it |
|---|---|---|
| `SeDebugPrivilege` | Open any process regardless of DACL | Required for LSASS memory access (credential dumping) |
| `SeImpersonatePrivilege` | Impersonate client tokens | Potato attacks (token impersonation for privilege escalation) |
| `SeAssignPrimaryTokenPrivilege` | Assign tokens to processes | Create processes as other users |
| `SeBackupPrivilege` | Read any file regardless of ACL | Read SAM/SYSTEM hives, NTDS.dit |
| `SeRestorePrivilege` | Write any file regardless of ACL | Overwrite protected files |
| `SeTcbPrivilege` | Act as part of the operating system | Full system compromise |
| `SeLoadDriverPrivilege` | Load kernel drivers | BYOVD (Bring Your Own Vulnerable Driver) attacks |

### Integrity levels

| Level | Value | Typical processes | Detection implication |
|---|---|---|---|
| System | 16384 | SYSTEM services, kernel | Expected for services; unexpected for user-launched processes |
| High | 12288 | Elevated admin processes | UAC bypassed or legitimately elevated |
| Medium | 8192 | Standard user processes | Normal user context |
| Low | 4096 | Protected Mode IE, sandboxed | Sandbox escape if a Low process spawns a Medium+ child |
| Untrusted | 0 | Highly restricted | Should never spawn children |

---

## 3. DLL loading and hijacking

### DLL search order (standard)

When a process loads a DLL, Windows searches in this order:
1. Known DLLs registry (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`)
2. Application directory (where the .exe lives)
3. System directory (`C:\Windows\System32`)
4. 16-bit system directory (`C:\Windows\System`)
5. Windows directory (`C:\Windows`)
6. Current directory
7. PATH environment variable directories

### Detection-relevant implications

| Attack | Mechanism | Detection signal |
|---|---|---|
| **DLL search order hijacking** | Place malicious DLL in application directory before system directory | DLL loaded from unexpected path (not System32) |
| **DLL side-loading** | Abuse legitimate signed application that loads a specific DLL name | Legitimate executable in unusual location loading unsigned DLL |
| **DLL injection** | `CreateRemoteThread` + `LoadLibrary` in target process | Sysmon EID 8 (CreateRemoteThread), EID 7 (ImageLoad) from unexpected path |
| **Phantom DLL loading** | Application tries to load a DLL that doesn't exist — attacker places it | DLL loaded from writable location that doesn't normally contain it |

---

## 4. Service Control Manager (SCM)

Windows services are managed by the SCM (`services.exe`). Key internals:

| Concept | Detail | Detection relevance |
|---|---|---|
| **Service creation** | `sc create` or `CreateService` API → registry entry under `HKLM\SYSTEM\CurrentControlSet\Services` | EID 7045 (System) / 4697 (Security). PsExec creates `PSEXESVC` service. |
| **Service account** | `LocalSystem`, `LocalService`, `NetworkService`, or domain account | `LocalSystem` services have full system privileges. New services running as `LocalSystem` are high-signal. |
| **Session 0 isolation** | All services run in Session 0, isolated from user desktop | Services cannot interact with user desktop (since Vista). Attempts to do so are suspicious. |
| **Service DLL** | `svchost.exe` loads service DLLs from `ServiceDll` registry value | Malicious `ServiceDll` values pointing to attacker DLLs — persistence mechanism |
| **Service failure recovery** | `FailureActions` registry value can specify a command to run on failure | Persistence via failure recovery commands |

---

## 5. COM/DCOM/WMI execution

### COM (Component Object Model)

COM objects are registered in the registry and instantiated by CLSID. Detection-relevant:
- **COM hijacking**: Replacing a legitimate COM DLL with a malicious one via registry modification (`HKCU\Software\Classes\CLSID\{...}\InprocServer32`)
- **DCOM lateral movement**: Remote COM object instantiation via `MMC20.Application`, `ShellWindows`, `ShellBrowserWindow` — creates processes on remote hosts
- **Detection signal**: `dllhost.exe` spawning unexpected child processes; remote DCOM connections (RPC on port 135 + dynamic ports)

### WMI (Windows Management Instrumentation)

| WMI surface | Detection relevance |
|---|---|
| **WMI process creation** | `Win32_Process.Create` — creates processes remotely. Parent is `WmiPrvSE.exe`. |
| **WMI event subscriptions** | `__EventFilter` + `__EventConsumer` + `__FilterToConsumerBinding` — persistence mechanism. Sysmon EID 19/20/21. |
| **WMI queries** | `SELECT * FROM Win32_Process` — reconnaissance. High volume but specific queries (e.g. antivirus enumeration) are suspicious. |

---

## 6. Named pipes

Named pipes are an IPC mechanism used extensively by Windows and by C2 frameworks.

| Concept | Detail | Detection relevance |
|---|---|---|
| **Pipe namespace** | `\\.\pipe\<name>` | Sysmon EID 17 (PipeCreated), EID 18 (PipeConnected) |
| **Default C2 pipes** | Cobalt Strike: `\\.\pipe\MSSE-*`, `\\.\pipe\msagent_*`, `\\.\pipe\postex_*` | Known-bad pipe name patterns |
| **SMB pipes** | Named pipes over SMB (port 445) enable remote IPC | Lateral movement via named pipes (PsExec uses `\\.\pipe\svcctl`) |
| **Pipe impersonation** | Server can impersonate the client's token | Potato attacks use pipe impersonation for privilege escalation |

---

## 7. ETW (Event Tracing for Windows)

ETW is the underlying telemetry framework that feeds Security events, Sysmon, and EDR sensors.

| Provider | GUID | What it captures | Consumer |
|---|---|---|---|
| Microsoft-Windows-Security-Auditing | `{54849625-...}` | Security events (4624, 4688, etc.) | Security event log |
| Microsoft-Windows-Sysmon | `{5770385f-...}` | Sysmon events | Sysmon event log |
| Microsoft-Windows-PowerShell | `{a0c1853b-...}` | PowerShell execution | PowerShell event log |
| Microsoft-Antimalware-Scan-Interface | `{2a576b87-...}` | AMSI scan results | AMSI consumers |
| Microsoft-Windows-Kernel-Process | `{22fb2cd6-...}` | Process creation/termination | EDR sensors |
| Microsoft-Windows-DNS-Client | `{1c95126e-...}` | DNS queries | EDR sensors, Sysmon |

**Detection implication**: Attackers who disable ETW providers (e.g. patching `ntdll!EtwEventWrite`) blind all consumers simultaneously. Detecting ETW tampering is a critical defence impairment signal.

---

## 8. AMSI (Antimalware Scan Interface)

AMSI provides a standardised interface for applications to submit content for malware scanning.

| Concept | Detail | Detection relevance |
|---|---|---|
| **AMSI providers** | PowerShell, VBScript, JScript, .NET, Office VBA macros | Content scanned before execution |
| **AMSI bypass** | Patching `amsi.dll` in memory (`AmsiScanBuffer` → return 0) | Detectable via: PowerShell ScriptBlock logging showing bypass strings (`AmsiUtils`, `amsiInitFailed`), ETW provider tampering |
| **AMSI evasion** | String obfuscation, reflection, `Add-Type` compilation | ScriptBlock logging captures deobfuscated content — more reliable than command-line |

---

## 9. Registry structure

| Hive | Path | Detection relevance |
|---|---|---|
| `HKLM\SOFTWARE` | Machine-wide software config | Persistence (Run keys, COM objects) |
| `HKLM\SYSTEM` | System configuration | Services, drivers, boot config |
| `HKLM\SAM` | Security Account Manager | Local account hashes — credential dumping target |
| `HKLM\SECURITY` | LSA secrets, cached credentials | Credential dumping target |
| `HKCU\SOFTWARE` | Per-user software config | User-level persistence (Run keys, COM hijacking) |
| `HKU\.DEFAULT` | Default user profile | Persistence for services running as SYSTEM |

### Key persistence locations

| Location | Registry path | Detection signal |
|---|---|---|
| Run keys | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | EID 13 (Sysmon), 4657 (Security) |
| RunOnce | `...\RunOnce` | Same — executes once then deletes |
| Services | `HKLM\SYSTEM\CurrentControlSet\Services\<name>` | EID 7045/4697 |
| Scheduled tasks | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache` | EID 4698 |
| COM objects | `HKCU\Software\Classes\CLSID\{...}\InprocServer32` | COM hijacking |
| Image File Execution Options | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>` | Debugger persistence, accessibility feature abuse |
| AppInit_DLLs | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` | DLL injection into every process loading user32.dll |
| Winlogon | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` | Shell replacement persistence |

---

## 10. Quality checklist

- [ ] Detection targets the OS-level behaviour, not a specific tool name.
- [ ] Process correlation uses stable identifiers (not PIDs).
- [ ] Parent-child relationship validated against known-good baselines.
- [ ] Privilege requirements understood (e.g. `SeDebugPrivilege` for LSASS access).
- [ ] DLL loading detections account for search order, not just file name.
- [ ] Service creation detections check service account and image path.
- [ ] Named pipe detections cover both creation and connection events.
- [ ] Registry persistence detections cover both HKLM and HKCU paths.
- [ ] ETW/AMSI tampering considered as a defence impairment signal.
- [ ] Integrity level transitions validated (Low→Medium = sandbox escape).
