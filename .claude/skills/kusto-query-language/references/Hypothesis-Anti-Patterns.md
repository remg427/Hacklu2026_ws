# Hypothesis Anti-Patterns (AP-H1 — AP-H5)

A catalogue of common anti-patterns in threat-hunting and detection-design hypothesis generation. These apply equally to Microsoft Sentinel, Microsoft Defender Advanced Hunting, or any cross-platform formulation. Use as a rejection checklist.

> **Rule**: If a hypothesis matches any anti-pattern, it must be revised before queries are written or detection rules emitted.

---

## AP-H1: The Tautology

**Pattern**: Hypothesis restates the threat report title without adding testable specificity.

| Bad | Good |
|---|---|
| "APT actor may be targeting our organisation" | "Adversary may be using Cobalt Strike beacon DNS tunnelling to exfiltrate from domain controllers in the EMEA region, based on subdomain-encoded queries to `*.<documented-domain>` observed in the source report" |
| "Ransomware groups are a threat to retail" | "Ransomware affiliate may attempt MOVEit Transfer exploitation (CVE-2023-34362) against internet-facing file-transfer infrastructure for bulk data exfiltration before ransom deployment" |
| "Credential attacks are a threat" | "Adversary may be conducting MFA fatigue attacks against service-desk accounts, evidenced by repeated push approvals followed by anomalous Azure AD role assignments" |

**Why it fails**: A tautology cannot be falsified. If the hypothesis cannot produce a "not found" result, it is not a hypothesis.

**Fix**: Add Actor + Behaviour + Location + Evidence (ABLE framework — see `threat-hunting/SKILL.md`).

---

## AP-H2: The Kitchen Sink

**Pattern**: Hypothesis tries to cover every TTP from a report in one statement.

| Bad | Good |
|---|---|
| "Adversary may use LOTL techniques including PowerShell, WMI, certutil and living-off-the-land binaries to persist and move laterally" | "Adversary may use `ntdsutil.exe` to create Active Directory snapshots on domain controllers, enabling offline credential extraction — detected via process-execution anomalies on DC assets" |
| "Threat group may use token theft, MFA bypass, OAuth abuse, and lateral movement through Azure AD" | "Threat group may abuse OAuth application consents to establish persistent access to the M365 tenant — detectable via anomalous application-consent grants from non-admin users" |

**Why it fails**: Multi-TTP hypotheses cannot have a focused query. Each query is either too broad (covers all weakly) or incomplete (covers some). Results become impossible to triage.

**Fix**: One hypothesis per TTP. A hunt or detection package may contain multiple hypotheses, but each must be independently testable.

---

## AP-H3: The Orphan

**Pattern**: Hypothesis has no connection to specific intelligence; reads like a textbook exercise.

| Bad | Good |
|---|---|
| "Attackers may use credential dumping to access sensitive systems" | "Per [source ref], the 2026 campaign uses Mimikatz `sekurlsa::logonpasswords` specifically against Windows Server 2019+ domain controllers with credential caching enabled" |
| "Attackers may use password spraying to access accounts" | "Per [source ref], the 2026 campaign uses residential proxy infrastructure for credential spray attacks targeting logistics-sector Azure AD tenants" |

**Why it fails**: No source = no confidence basis, no relevance basis, no auditability. The hypothesis cannot be distinguished from generic LLM output.

**Fix**: Every hypothesis must trace to specific intelligence via `source_references` with **verbatim quotes**.

---

## AP-H4: The Technology Hunt

**Pattern**: Hypothesis hunts for the presence of a technology rather than malicious behaviour using that technology.

| Bad | Good |
|---|---|
| "We should detect PowerShell usage across the environment" | "We should detect base64-encoded PowerShell commands executed via `mshta.exe → PowerShell` chain where the decoded payload contains `WebClient` download operations, consistent with the documented first-stage loader" |
| "We should detect Conditional Access policy changes" | "We should detect Conditional Access policy modifications that weaken MFA requirements for privileged roles, consistent with documented pre-attack infrastructure preparation" |

**Why it fails**: Detecting a technology generates thousands of legitimate results. The hypothesis cannot distinguish malicious from benign.

**Fix**: Hunt for the **specific behavioural chain** documented in the intelligence, not the tool itself.

---

## AP-H5: The Time Traveler

**Pattern**: Hypothesis references a threat with no current or recent activity, without justification.

| Bad | Good |
|---|---|
| "NotPetya-style wipers may target the environment" | "Given documented 2026 resurgence of wiper activity targeting European logistics ([source ref]), destructive malware with NotPetya-like propagation via EternalBlue still poses risk to legacy Windows Server 2012 instances" |
| "SolarWinds SAML token forging may target the environment" | "Given documented 2026 resurgence of Golden SAML attacks targeting European enterprises ([source ref]), SAML token forging still poses risk to organisations using ADFS" |

**Why it fails**: Without current intelligence, the hypothesis is speculation. Confidence cannot be assessed.

**Fix**: Either cite current intelligence, or explicitly justify why a historical threat has renewed relevance (technique reuse, copycat campaigns, new vulnerability enabling old technique).

---

## Quick reference

| Red flag | Anti-pattern | Fix |
|---|---|---|
| Could apply to any organisation | AP-H1 (Tautology) | Add ABLE specificity |
| Covers > 1 TTP in one statement | AP-H2 (Kitchen Sink) | Split into multiple hypotheses |
| No source reference / quotes | AP-H3 (Orphan) | Add `source_references` |
| Hunts a tool, not a behaviour | AP-H4 (Technology Hunt) | Narrow to behavioural chain |
| Cites a threat with no current activity | AP-H5 (Time Traveler) | Cite current intel or justify renewal |
