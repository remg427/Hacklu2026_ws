---
name: mitre-attack
description: MITRE ATT&CK mapping discipline and technique reference for opentide TVM, DOM, and MDR objects — technique vs sub-technique selection, tactic assignment, multi-technique chaining, version pinning, revocation handling, coverage gap analysis, platform matrix awareness, and a locally searchable technique index. Use when populating threat.att&ck fields in TVMs, mapping DOM signals to techniques, tagging MDR rules, assessing detection coverage against the ATT&CK matrix, or looking up technique IDs and descriptions.
---

# MITRE ATT&CK — mapping discipline + technique reference

This skill encodes the discipline of mapping adversary behaviour to ATT&CK and back, plus a locally searchable technique index. Every opentide object type carries ATT&CK references; getting them right is a quality gate.

**Current baseline**: ATT&CK **v19** (April 2026, Enterprise domain: 15 tactics, 222 techniques, 475 sub-techniques).

> **v19 breaking change**: Defense Evasion was split into **Stealth** (TA0005) and **Defense Impairment** (TA0112). Any existing mappings referencing TA0005 as "Defense Evasion" must be reviewed and re-assigned.

> **Online version check**: If this skill may be outdated, verify the current ATT&CK version at:
> - Release notes: https://attack.mitre.org/resources/updates/
> - Version history: https://attack.mitre.org/versions/
> - Machine-readable STIX: https://github.com/mitre/cti (enterprise-attack branch)
> - Blog announcements: https://medium.com/mitre-attack

---

## 1. Tactic, technique, sub-technique — when to use which

| Level | Use when | Example |
|---|---|---|
| **Tactic only** | Early TVM drafting where the specific technique is unknown or the intelligence is vague | "Adversary seeks credential access" → `TA0006` |
| **Technique** | The behaviour class is clear but the specific implementation is not documented | "Adversary uses credential dumping" → `T1003` |
| **Sub-technique** | The specific implementation is documented in the intelligence | "Adversary dumps LSASS memory" → `T1003.001` |

### Decision rules

1. **Always prefer the most specific level the evidence supports.** If the source says "Mimikatz sekurlsa::logonpasswords", map to `T1003.001`, not `T1003`.
2. **Never map to a sub-technique without also implying the parent.** The parent is implicit in ATT&CK's hierarchy — do not list both `T1003` and `T1003.001` for the same behaviour.
3. **Map to the parent technique only when** the source describes the behaviour class but not the specific method, or when multiple sub-techniques apply and you cannot distinguish which.
4. **Do not over-tag.** If a detection rule catches one specific sub-technique, map to that sub-technique only. LLMs tend to list every plausible sub-technique — resist this.

---

## 2. Tactic assignment

A technique can appear under multiple tactics. Select the tactic that matches the **adversary's goal in context**, not every tactic the technique could theoretically serve.

| Scenario | Correct tactic | Wrong |
|---|---|---|
| Adversary uses `schtasks` to persist | Persistence (TA0003) | Execution (TA0002) — even though schtasks executes |
| Adversary uses `schtasks` to run a payload once | Execution (TA0002) | Persistence (TA0003) — no persistence intent |
| Adversary uses PowerShell to download a payload | Command and Scripting Interpreter (T1059.001) under Execution | Don't also tag Initial Access |

### v19 tactic split

| Old tactic | New tactics (v19) | Action |
|---|---|---|
| Defense Evasion (TA0005) | **Stealth** (TA0005) — hiding artefacts, obfuscation, masquerading | Review existing TA0005 mappings |
| | **Defense Impairment** (TA0112) — disabling tools, clearing logs, firewall modification | Re-assign where the goal is impairing defences |

---

## 3. Multi-technique chaining

A single TVM or MDR may reference multiple techniques when the intelligence documents a **behavioural chain**. Rules:

1. **Each technique in the chain must be independently evidenced.** Do not infer intermediate steps.
2. **Order matters in TVMs.** The `chaining` field should reflect the temporal sequence documented in the intelligence.
3. **MDR rules typically map to 1-2 techniques.** A detection rule that claims to cover 5+ techniques is almost certainly an AP-H2 Kitchen Sink (see `threat-hunting` skill).
4. **DOM signals map to the technique(s) the signal can actually detect**, not the full chain the parent TVM describes.

---

## 4. Version pinning and revocation handling

### Version pinning

- opentide content should reference ATT&CK technique IDs without version suffixes (e.g. `T1059.001`, not `T1059.001 v2.0`).
- The **repository-level** ATT&CK version is declared in the content repo's metadata or schema configuration. Individual objects inherit this.
- When ATT&CK releases a new version, review objects whose mapped techniques had **major version changes** or **revocations**.

### Revocations

ATT&CK periodically revokes techniques, replacing them with new IDs. v19 examples:
- `Impair Defenses` → revoked, replaced by `Disable or Modify Tools` (T1685)
- `Disable or Modify System Firewall` → revoked, replaced by T1686

**Handling revocations in opentide:**
1. Search the content repo for the revoked technique ID.
2. Update to the replacement technique ID.
3. Review the description — the replacement may have a narrower or broader scope.
4. Log the change in the PR narrative.

### Deprecations

Deprecated techniques have no replacement. Remove the mapping and document the gap.

---

## 5. Mapping in opentide objects

### TVM (Threat Vector)

| Field | ATT&CK content |
|---|---|
| `threat.att&ck` | Array of technique/sub-technique IDs with tactic context |
| `terrain` | Narrative references to ATT&CK behaviours with evidence |
| `chaining` | Ordered technique sequence when the TVM describes a multi-step chain |

**Quality bar**: Every technique ID in `threat.att&ck` must trace to a specific claim in the source intelligence. Unmapped techniques are preferable to speculative mappings.

### DOM (Detection Objective)

| Field | ATT&CK content |
|---|---|
| `objective.signals[].att&ck` | Technique(s) the signal can detect |
| Coverage narrative | Which sub-techniques are covered vs gaps |

**Quality bar**: A DOM signal should map to the technique(s) it can actually observe, not the full TVM chain. If a signal detects `T1003.001` (LSASS dump) but not `T1003.003` (NTDS), map only `.001`.

### MDR (Detection Rule)

| Field | ATT&CK content |
|---|---|
| Rule metadata / `configurations.*.mitre` | Technique IDs for the platform rule |
| `description` | Technique context in prose |

**Quality bar**: The MDR technique mapping must match what the query actually detects. A KQL query filtering on `FileName =~ "ntdsutil.exe"` maps to `T1003.003`, not the parent `T1003`.

---

## 6. Coverage analysis (inverse mapping)

ATT&CK mapping also works in reverse: given a set of detection rules, which techniques are covered?

### Coverage matrix construction

1. Extract all technique IDs from MDR objects in the content repo.
2. Map against the ATT&CK Enterprise matrix (222 techniques, 475 sub-techniques in v19).
3. Classify coverage:

| Level | Definition |
|---|---|
| **Detected** | At least one production MDR rule maps to this technique |
| **Hunted** | A validated hunt query exists but no production rule |
| **Theoretical** | A DOM signal is defined but no query exists |
| **Gap** | No coverage at any level |

### Coverage anti-patterns

| Anti-pattern | Description |
|---|---|
| **Breadth without depth** | Mapping to parent techniques only, claiming "T1059 covered" when only PowerShell (T1059.001) has a rule |
| **Phantom coverage** | Mapping a rule to a technique it cannot actually detect (e.g. a network rule claiming to detect a registry technique) |
| **Stale coverage** | Rules mapped to revoked technique IDs that no longer exist in the current ATT&CK version |
| **Platform mismatch** | Claiming Linux technique coverage with a Windows-only detection rule |

---

## 7. Common mapping mistakes

| Mistake | Fix |
|---|---|
| Listing both parent and sub-technique for the same behaviour | Use the most specific level only |
| Mapping to every tactic a technique supports | Select the tactic matching the adversary's goal in context |
| Copying technique lists from CTI reports without validation | Verify each mapping against the actual behaviour described |
| Using deprecated/revoked technique IDs | Check against current ATT&CK version |
| Mapping a detection rule to techniques it cannot observe | Map only to what the query's data source can see |
| Over-tagging MDR rules with 5+ techniques | One rule typically detects 1-2 specific behaviours |

---

## 8. ATT&CK data sources and data components

ATT&CK v19 includes **Data Components** (e.g. Process Creation, File Modification, Network Connection Creation) that link techniques to observable telemetry. Use these to validate that your detection platform actually has visibility into the mapped technique.

| Data component | Telemetry type | Example sources |
|---|---|---|
| Process Creation | Process execution logs | EDR process events, Security EID 4688, Sysmon EID 1 |
| File Creation / Modification | File system activity logs | EDR file events, Sysmon EID 11, Security EID 4663 |
| Network Connection Creation | Network connection logs | EDR network events, Sysmon EID 3, firewall logs |
| User Account Authentication | Authentication logs | SIEM sign-in logs, Security EID 4624/4625 |
| Windows Registry Key Modification | Registry change logs | EDR registry events, Sysmon EID 12/13/14, Security EID 4657 |
| Module Load | DLL/image load logs | EDR image load events, Sysmon EID 7 |
| Command Execution | Command-line / script logs | PowerShell 4104, EDR command events |
| Scheduled Job Creation | Task/job creation logs | Security EID 4698, Sysmon EID (via WMI), cron logs |
| Service Creation | Service installation logs | System EID 7045, Security EID 4697 |
| Active Directory Object Access | Directory service logs | SIEM audit logs, Security EID 4662 |

> Consult your platform skill for exact table/index names. If the data component required by a technique is not available on your platform, the mapping is theoretical — document the gap.

---

## 9. Platform matrix awareness

ATT&CK Enterprise covers multiple platform domains. Ensure technique mappings align with the target platform:

| Platform | Scope | Notes |
|---|---|---|
| **Windows** | Desktop + Server | Largest technique coverage; most sub-techniques |
| **Linux** | Servers, containers, IoT | Growing coverage; includes container-specific techniques |
| **macOS** | Desktop | Smaller but distinct technique set (TCC, launchd, etc.) |
| **Cloud** (AWS, Azure, GCP) | IaaS / PaaS | Cloud-specific techniques (T1578, T1580, T1535, etc.) |
| **SaaS** | Office 365, Google Workspace, etc. | Identity and data-focused techniques |
| **Network** | Routers, switches, firewalls | Network device-specific techniques |
| **Containers** | Docker, Kubernetes | Container escape, orchestration abuse |
| **ICS** | Industrial control systems | Separate ATT&CK for ICS matrix (not covered here) |

**Rule**: When mapping a detection rule to a technique, verify the technique applies to the platform the rule targets. A Windows-only detection cannot claim coverage of a Linux-only technique.

---

## 10. Tactic reference (v19 Enterprise)

| ID | Tactic | Description |
|---|---|---|
| TA0043 | Reconnaissance | Gathering information to plan future operations |
| TA0042 | Resource Development | Establishing resources to support operations |
| TA0001 | Initial Access | Gaining an initial foothold |
| TA0002 | Execution | Running adversary-controlled code |
| TA0003 | Persistence | Maintaining access across restarts/credential changes |
| TA0004 | Privilege Escalation | Gaining higher-level permissions |
| TA0005 | Stealth | Hiding artefacts, obfuscation, masquerading (v19: split from Defense Evasion) |
| TA0112 | Defense Impairment | Disabling tools, clearing logs, firewall modification (v19: split from Defense Evasion) |
| TA0006 | Credential Access | Stealing credentials |
| TA0007 | Discovery | Exploring the environment |
| TA0008 | Lateral Movement | Moving through the environment |
| TA0009 | Collection | Gathering data of interest |
| TA0011 | Command and Control | Communicating with compromised systems |
| TA0010 | Exfiltration | Stealing data |
| TA0040 | Impact | Manipulating, interrupting, or destroying systems and data |

## 11. Quality checklist

- [ ] Every technique ID is valid in the current ATT&CK version.
- [ ] Sub-technique used when the specific implementation is documented; parent when not.
- [ ] Parent and sub-technique not both listed for the same behaviour.
- [ ] Tactic matches the adversary's goal in context, not every possible tactic.
- [ ] MDR technique mapping matches what the query actually detects.
- [ ] DOM signal mapping covers only the techniques the signal can observe.
- [ ] TVM technique mapping traces to specific source intelligence claims.
- [ ] No revoked or deprecated technique IDs remain.
- [ ] Coverage claims validated against available data sources / data components.
- [ ] Multi-technique chains are independently evidenced per step.
- [ ] Platform matrix alignment verified (technique applies to the target platform).
- [ ] v19 tactic split handled: TA0005 = Stealth, TA0112 = Defense Impairment (not "Defense Evasion").
- [ ] Technique index (`references/Enterprise-Techniques.md`) consulted for ID validation.
- [ ] Online ATT&CK version checked if skill may be outdated.
