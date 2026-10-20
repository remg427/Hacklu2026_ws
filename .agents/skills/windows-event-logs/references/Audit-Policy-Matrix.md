# Windows Audit Policy Matrix — Event ID Prerequisites

Every detection that depends on a specific Event ID must declare the audit policy prerequisite. Without the correct policy enabled, the events simply do not generate.

> Source: [Microsoft audit policy recommendations](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations)

---

## Account Logon

| Subcategory | Key EIDs | Default | Recommended | Notes |
|---|---|---|---|---|
| Credential Validation | 4776 | No Auditing | Success + Failure | NTLM authentication. Critical for pass-the-hash, NTLM relay detection. |
| Kerberos Authentication Service | 4768, 4771 | No Auditing | Success + Failure | TGT requests. 4771 failure = pre-auth failed (password spray via Kerberos). |
| Kerberos Service Ticket Operations | 4769 | No Auditing | Success + Failure | Service ticket requests. RC4 encryption type (0x17) = Kerberoasting indicator. |

## Logon/Logoff

| Subcategory | Key EIDs | Default | Recommended | Notes |
|---|---|---|---|---|
| Logon | 4624, 4625 | Success | Success + Failure | Core authentication events. Type 3/10 = lateral movement. |
| Logoff | 4634, 4647 | No Auditing | Success | Session duration analysis. |
| Special Logon | 4672 | Success | Success | Privileged logon detection. Fires when special privileges assigned. |
| Other Logon/Logoff Events | 4649, 4778, 4779, 4800, 4801 | No Auditing | Success + Failure | Replay attacks (4649), RDP reconnect (4778/4779), lock/unlock (4800/4801). |
| Account Lockout | 4625 (sub-status 0xC0000234) | Success | Success + Failure | Brute-force threshold reached. |

## Account Management

| Subcategory | Key EIDs | Default | Recommended | Notes |
|---|---|---|---|---|
| User Account Management | 4720, 4722, 4724, 4725, 4726, 4738, 4740, 4767 | Success | Success + Failure | Account creation, enable, password reset, disable, delete, modify, lockout, unlock. |
| Security Group Management | 4728, 4729, 4732, 4733, 4756, 4757 | Success | Success | Member added/removed from global/local/universal security groups. |
| Computer Account Management | 4741, 4742, 4743 | No Auditing | Success | Computer account create/modify/delete. Rogue domain joins. |
| Distribution Group Management | 4749, 4750, 4751, 4752, 4753 | No Auditing | Success | Distribution group changes. Less security-critical but useful for BEC. |

## Detailed Tracking

| Subcategory | Key EIDs | Default | Recommended | Notes |
|---|---|---|---|---|
| Process Creation | 4688 | No Auditing | Success | **Critical.** Also requires GPO: "Include command line in process creation events". Without command-line logging, most detection value is lost. |
| Process Termination | 4689 | No Auditing | Success | Process lifecycle. Useful for short-lived processes (LOLBins). |
| DPAPI Activity | 4692, 4693, 4694, 4695 | No Auditing | Success + Failure | DPAPI master key operations. Credential theft via DPAPI. |
| RPC Events | 5712 | No Auditing | Optional | RPC connection attempts. Noisy but useful for lateral movement analysis. |

## Object Access

| Subcategory | Key EIDs | Default | Recommended | Notes |
|---|---|---|---|---|
| File System | 4663, 4656, 4658 | No Auditing | Success + Failure | Requires SACL on target objects. High volume — scope carefully. |
| Registry | 4657, 4656, 4658 | No Auditing | Success + Failure | Registry access auditing. Requires SACL. Critical for persistence detection. |
| File Share | 5140, 5142, 5143 | No Auditing | Success + Failure | Network share access. 5140 = share accessed. Lateral movement via SMB. |
| Detailed File Share | 5145 | No Auditing | Success + Failure | File-level share access. More granular than 5140 but higher volume. |
| SAM | 4661 | No Auditing | Success + Failure | SAM database access. Credential dumping indicator. |
| Kernel Object | 4656, 4658, 4660, 4663 | No Auditing | Optional | Kernel object access. Very noisy. Only enable for targeted investigations. |
| Handle Manipulation | 4658, 4690 | No Auditing | Optional | Handle close/duplicate. Useful for process injection analysis. |
| Removable Storage | 4663 | No Auditing | Success | USB/removable media access. Data exfiltration detection. |

## Policy Change

| Subcategory | Key EIDs | Default | Recommended | Notes |
|---|---|---|---|---|
| Audit Policy Change | 4719, 4902, 4906, 4907, 4912 | Success | Success + Failure | **Critical.** 4719 = audit policy changed. Defence impairment detection. |
| Authentication Policy Change | 4713, 4716, 4717, 4718, 4739, 4864, 4865 | Success | Success | Trust/Kerberos policy changes. Domain trust manipulation. |
| MPSSVC Rule-Level Policy Change | 4944, 4945, 4946, 4947, 4948, 4949, 4950, 4951 | No Auditing | Success + Failure | Windows Firewall rule changes. Defence impairment. |

## Privilege Use

| Subcategory | Key EIDs | Default | Recommended | Notes |
|---|---|---|---|---|
| Sensitive Privilege Use | 4673, 4674, 4985 | No Auditing | Success + Failure | SeDebugPrivilege, SeTcbPrivilege, etc. Privilege escalation detection. |
| Non-Sensitive Privilege Use | 4673, 4674 | No Auditing | Optional | High volume. Only enable for targeted analysis. |

## System

| Subcategory | Key EIDs | Default | Recommended | Notes |
|---|---|---|---|---|
| Security System Extension | 4697 | Success | Success + Failure | Service installed (Security log). Persistence, PsExec, lateral movement. |
| System Integrity | 4612, 4615, 4616, 4618, 4816 | Success | Success + Failure | Audit system integrity. Tamper detection. |
| Security State Change | 4608, 4609, 4616, 4621 | Success | Success | System startup/shutdown, time change. Anti-forensics detection. |

---

## System log events (no audit policy — always generated)

| EID | Channel | Description | Detection use |
|---|---|---|---|
| 7045 | System | Service installed | Persistence, PsExec, lateral movement. Complements 4697. |
| 7040 | System | Service start type changed | Persistence modification. |
| 7036 | System | Service entered running/stopped state | Service lifecycle. |
| 1102 | Security | Audit log cleared | **Anti-forensics.** Always fires regardless of audit policy. |
| 4720 | Security | User account created | Always fires when User Account Management auditing is enabled. |

---

## Sysmon — no audit policy required

Sysmon events are generated by the Sysmon driver, not Windows audit policy. However, Sysmon requires:
1. **Sysmon installed** on the endpoint.
2. **Sysmon configuration** specifying which events to collect (default config logs everything — never use in production).
3. **Hash algorithm** configured (recommend SHA256 minimum).

| EID | Requires config rule | Notes |
|---|---|---|
| 1 (ProcessCreate) | Yes — `<ProcessCreate>` | Primary process detection. Include/exclude rules critical for volume. |
| 3 (NetworkConnect) | Yes — `<NetworkConnect>` | Very noisy. Filter to outbound + non-private IPs. |
| 7 (ImageLoad) | Yes — `<ImageLoad>` | DLL loads. Extremely noisy without exclusions. |
| 10 (ProcessAccess) | Yes — `<ProcessAccess>` | LSASS access. Filter `TargetImage` to `lsass.exe` only. |
| 11 (FileCreate) | Yes — `<FileCreate>` | Payload drops. Filter by path/extension. |
| 17/18 (PipeEvent) | Yes — `<PipeEvent>` | Named pipe C2. Relatively low volume. |
| 22 (DNSQuery) | Yes — `<DnsQuery>` | DNS resolution. Filter known-good domains. |

---

## PowerShell logging — GPO required

| Feature | GPO path | Notes |
|---|---|---|
| Script Block Logging (4104) | `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging` | Captures deobfuscated script content. Highest-value PowerShell telemetry. |
| Module Logging (4103) | `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on Module Logging` | Specify modules: `*` for all, or specific modules. |
| Transcription | `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Transcription` | File-based output. Useful for forensics but not real-time detection. |

---

## Quick reference — minimum audit policy for detection engineering

| Detection goal | Required audit subcategories |
|---|---|
| Lateral movement (SMB) | Logon (4624/4625), File Share (5140), Detailed File Share (5145) |
| Lateral movement (RDP) | Logon (4624 Type 10), Other Logon/Logoff (4778/4779) |
| Credential dumping | Process Creation (4688 + cmdline), SAM (4661), Registry (4657) |
| Persistence (services) | Security System Extension (4697), Process Creation (4688) |
| Persistence (scheduled tasks) | Object Access (4698, 4702), Process Creation (4688) |
| Privilege escalation | Sensitive Privilege Use (4673), User Account Management (4728/4732) |
| Defence impairment | Audit Policy Change (4719), MPSSVC Rule-Level (4946-4948) |
| Password spray / brute force | Logon (4625), Credential Validation (4776), Kerberos Auth (4771) |
| Kerberoasting | Kerberos Service Ticket (4769 with encryption type 0x17) |
| Account manipulation | User Account Management (4720-4740), Security Group Management (4728-4757) |
