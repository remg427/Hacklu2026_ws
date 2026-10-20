---
name: active-directory
description: Active Directory internals for detection engineering — Kerberos authentication flow (AS-REQ/TGT/TGS/service ticket), NTLM challenge-response mechanics, AD replication protocol (DRS/DCSync), trust types and delegation abuse (constrained/unconstrained/RBCD), Group Policy processing, AD Certificate Services attack paths (ESC1-ESC13), SPN mechanics and Kerberoasting, LDAP reconnaissance patterns, and the telemetry each operation produces. Use when authoring detections for credential access, lateral movement, privilege escalation, or persistence that involves Active Directory.
---

# Active Directory — detection-relevant internals

This skill encodes how Active Directory authentication, replication, and trust mechanisms actually work at the level needed to write detections that catch the underlying protocol abuse, not just specific tools.

---

## 1. Kerberos authentication flow

```
Client                    KDC (Domain Controller)           Service
  │                              │                              │
  │── AS-REQ (username + pre-auth) ──▶│                         │
  │◀── AS-REP (TGT, encrypted with krbtgt hash) ──│            │
  │                              │                              │
  │── TGS-REQ (TGT + target SPN) ──▶│                          │
  │◀── TGS-REP (service ticket, encrypted with service hash) ──│
  │                              │                              │
  │── AP-REQ (service ticket) ──────────────────────────────────▶│
  │◀── AP-REP (mutual auth, optional) ──────────────────────────│
```

### Detection-relevant implications

| Step | Event ID | What to detect |
|---|---|---|
| **AS-REQ** | 4768 (TGT request) | Encryption type 0x17 (RC4) in a modern environment = potential AS-REP roasting or downgrade |
| **AS-REQ failure** | 4771 (pre-auth failed) | Password spray via Kerberos (no account lockout by default for pre-auth failures) |
| **TGS-REQ** | 4769 (service ticket) | Encryption type 0x17 (RC4) for service ticket = Kerberoasting indicator |
| **TGT forging** | No direct event | Golden Ticket: forged TGT using compromised `krbtgt` hash. Detectable via TGT lifetime anomalies, non-existent accounts getting TGTs, or TGT without prior AS-REQ |
| **Service ticket forging** | No direct event | Silver Ticket: forged service ticket using compromised service account hash. Detectable via service ticket without prior TGS-REQ |

### Kerberoasting mechanics

1. Attacker requests TGS for accounts with SPNs (Service Principal Names)
2. TGS is encrypted with the service account's password hash
3. Attacker cracks the TGS offline — no lockout, no detection of cracking
4. **Detection**: EID 4769 with encryption type `0x17` (RC4-HMAC) for service accounts. Modern environments should use AES (0x12). RC4 requests are anomalous in environments that have fully migrated to AES. Audit for legacy applications that legitimately require RC4 before alerting.

### AS-REP roasting mechanics

1. Accounts with "Do not require Kerberos preauthentication" enabled
2. Attacker requests AS-REP without providing pre-auth
3. AS-REP contains data encrypted with the user's password hash
4. **Detection**: EID 4768 with `PreAuthType` = 0 (no pre-auth). Also: audit accounts with the flag enabled.

---

## 2. NTLM authentication

```
Client                    Server                    Domain Controller
  │── NEGOTIATE ──────────▶│                              │
  │◀── CHALLENGE (nonce) ──│                              │
  │── AUTHENTICATE (response) ──▶│                        │
  │                         │── Netlogon validation ──────▶│
  │                         │◀── Validation result ────────│
```

### Detection-relevant implications

| Concept | Detail | Detection signal |
|---|---|---|
| **Pass-the-Hash** | Attacker uses NTLM hash directly (no password needed) | EID 4776 (NTLM validation) from unexpected source. NTLMv1 usage in modern environment. |
| **NTLM relay** | Attacker relays NTLM authentication to a different service | EID 4624 Type 3 where source IP doesn't match expected client. Coercion attacks (PetitPotam, PrinterBug) trigger NTLM auth from machine accounts. |
| **NTLM downgrade** | Forcing NTLM when Kerberos is available | NTLM authentication to services that should use Kerberos. `AuthenticationPackage` = `NTLM` in EID 4624. |

---

## 3. AD replication and DCSync

### DRS (Directory Replication Service) protocol

Domain controllers replicate using the DRS protocol (`MS-DRSR`). The `GetNCChanges` operation retrieves AD objects including password hashes.

**DCSync attack**: A non-DC account with `Replicating Directory Changes` + `Replicating Directory Changes All` rights calls `GetNCChanges` to extract password hashes.

**Detection**:
- EID 4662 (object access) with `Properties` containing the replication GUIDs:
  - `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes)
  - `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}` (DS-Replication-Get-Changes-All)
- Source is NOT a domain controller
- EID 4624 Type 3 from the attacking machine to the DC

### DCShadow attack

Registers a rogue domain controller to inject changes into AD replication. More stealthy than DCSync.

**Detection**: New `nTDSDSA` object created in the AD schema (EID 5137), or SPN changes adding GC/DC SPNs to non-DC accounts.

---

## 4. Trust types and delegation

### Trust types

| Trust type | Direction | Detection relevance |
|---|---|---|
| **Parent-child** | Two-way transitive | Implicit in forest. SID filtering disabled by default. |
| **Forest** | One-way or two-way | SID filtering enabled by default. SID history attacks blocked unless filtering disabled. |
| **External** | One-way non-transitive | Legacy. No SID filtering. |
| **Realm** | One-way or two-way | Kerberos realm trust (non-Windows). |

### Delegation types

| Type | Mechanism | Risk | Detection |
|---|---|---|---|
| **Unconstrained** | Service stores client's TGT | Any service the client can access | EID 4624 with delegation flag. Accounts with `TRUSTED_FOR_DELEGATION`. |
| **Constrained** | Service can request tickets for specific SPNs | Limited to configured SPNs | `msDS-AllowedToDelegateTo` attribute. Protocol transition (`S4U2Self` + `S4U2Proxy`). |
| **Resource-based constrained (RBCD)** | Target service controls who can delegate to it | Attackers can modify `msDS-AllowedToActOnBehalfOfOtherIdentity` | Attribute modification on computer objects. EID 5136 (directory service changes). |

### RBCD attack mechanics

1. Attacker compromises an account with write access to a target computer's AD object
2. Modifies `msDS-AllowedToActOnBehalfOfOtherIdentity` to allow a controlled account to delegate
3. Uses `S4U2Self` + `S4U2Proxy` to obtain service tickets as any user to the target
4. **Detection**: EID 5136 showing modification of `msDS-AllowedToActOnBehalfOfOtherIdentity`. Attribute should rarely change.

---

## 5. Group Policy processing

```
Computer starts → Applies computer GPOs (in order: Local → Site → Domain → OU)
User logs in → Applies user GPOs (same order)
```

### Detection-relevant GPO abuse

| Attack | Mechanism | Detection |
|---|---|---|
| **GPO modification** | Attacker with write access to GPO adds malicious scheduled task or script | EID 5136 (GPO object modified). Monitor `GPC-File-Sys-Path` for unexpected changes. |
| **GPO link manipulation** | Link a malicious GPO to a high-value OU | EID 5136 on OU's `gPLink` attribute. |
| **Immediate task** | GPO scheduled task with `ImmediateTask` — executes once on next GPO refresh | File creation in `\\<domain>\SYSVOL\<domain>\Policies\{GUID}\Machine\Preferences\ScheduledTasks\` |

---

## 6. AD Certificate Services (AD CS)

AD CS issues certificates that can be used for authentication. Misconfigured templates create attack paths.

### Key escalation paths

| ESC | Misconfiguration | Impact | Detection |
|---|---|---|---|
| **ESC1** | Template allows requestor to specify SAN (Subject Alternative Name) + low-privilege enrollment | Request certificate as any user | EID 4886/4887 (certificate request/issue) with SAN different from requestor |
| **ESC3** | Certificate Request Agent template + another template allowing enrollment on behalf | Enroll certificates for any user | Two-step: agent cert request then enrollment-on-behalf |
| **ESC4** | Template ACL allows modification by low-privilege users | Modify template to enable ESC1 | EID 4899 (template modified) |
| **ESC6** | CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` flag | Any template becomes ESC1 | CA configuration audit |
| **ESC8** | HTTP enrollment endpoint without EPA | NTLM relay to CA web enrollment | NTLM authentication to CA HTTP endpoint from unexpected source |
| **ESC11** | RPC enrollment without EPA | NTLM relay to CA RPC endpoint | Similar to ESC8 via RPC |
| **ESC13** | Issuance policy linked to group membership | Certificate grants group membership | OID-to-group mapping in `msPKI-Certificate-Policy` |

### Certificate-based authentication

Certificates can authenticate via:
- **PKINIT** (Kerberos): Certificate used instead of password for AS-REQ. EID 4768 with certificate info.
- **Schannel** (TLS): Certificate used for TLS client authentication.
- **Smart card logon**: Certificate on smart card or virtual smart card.

**Detection**: EID 4768 with `CertIssuerName` and `CertSerialNumber` populated. Alert on certificates issued by unexpected CAs or with unexpected SANs.

---

## 7. LDAP reconnaissance

| Query pattern | What it reveals | Detection signal |
|---|---|---|
| `(objectClass=user)` | All user accounts | High-volume LDAP query from non-admin workstation |
| `(servicePrincipalName=*)` | All accounts with SPNs (Kerberoasting targets) | SPN enumeration from non-service account |
| `(userAccountControl:1.2.840.113556.1.4.803:=4194304)` | Accounts not requiring pre-auth (AS-REP roasting targets) | Specific UAC flag query |
| `(objectClass=trustedDomain)` | All domain trusts | Trust enumeration |
| `(objectCategory=computer)` | All computer accounts | Network reconnaissance |
| `(memberOf=CN=Domain Admins,...)` | Domain Admin members | Privilege target enumeration |
| `(objectClass=pKICertificateTemplate)` | Certificate templates | AD CS reconnaissance |

**Detection**: EID 1644 (LDAP query logging, requires diagnostic logging enabled) or network-level LDAP monitoring. Volume and specificity of queries from a single source are the key signals.

---

## 8. Telemetry sources

| AD operation | Windows Event ID | Sysmon EID | Log source |
|---|---|---|---|
| Kerberos TGT request | 4768 | — | Domain controller Security log |
| Kerberos service ticket | 4769 | — | Domain controller Security log |
| Kerberos pre-auth failure | 4771 | — | Domain controller Security log |
| NTLM authentication | 4776 | — | Domain controller Security log |
| Logon event | 4624/4625 | — | Endpoint Security log |
| Directory service change | 5136/5137 | — | Domain controller Security log |
| Object access (replication) | 4662 | — | Domain controller Security log |
| Certificate request | 4886/4887 | — | CA server Security log |
| GPO modification | 5136 | 12/13 (registry) | Domain controller Security log |
| LDAP query | 1644 (diagnostic) | — | Domain controller (requires diagnostic logging enabled) |

> Map these Event IDs to your SIEM's tables/indexes. Consult the relevant platform skill (`microsoft-sentinel`, `splunk-spl-processing`, etc.) for ingestion specifics.

---

## 9. Quality checklist

- [ ] Detection targets the protocol-level behaviour, not a specific tool.
- [ ] Kerberos encryption type checked (0x17 RC4 = anomalous in modern environments).
- [ ] NTLM usage flagged when Kerberos should be available.
- [ ] Replication rights (DCSync) monitored for non-DC accounts.
- [ ] Delegation attribute changes monitored (`msDS-AllowedToActOnBehalfOfOtherIdentity`, `msDS-AllowedToDelegateTo`).
- [ ] Certificate template misconfigurations assessed (ESC1-ESC13).
- [ ] LDAP query patterns correlated with source account privilege level.
- [ ] GPO modifications tracked via directory service change events.
- [ ] Trust relationships documented and SID filtering status verified.
- [ ] `sIDHistory` attribute modifications monitored (EID 5136) — injection of privileged SIDs enables persistence.
- [ ] Machine account NTLM coercion considered (PetitPotam, PrinterBug, DFSCoerce).
