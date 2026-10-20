---
name: network-protocols
description: Network protocol internals for detection engineering — DNS resolution chain and tunnelling indicators, TLS handshake and certificate anomalies, SMB authentication and lateral movement surface, HTTP/S C2 patterns (beaconing, jitter, domain fronting), LDAP bind and search patterns, RDP session mechanics, WinRM/PSRemoting transport, SMTP relay and header analysis, and the telemetry each protocol produces across detection platforms. Use when authoring detections that need to understand protocol-level behaviour to distinguish malicious from legitimate traffic.
---

# Network Protocols — detection-relevant internals

This skill encodes how network protocols actually work at the level needed to write detections that catch protocol abuse, not just known-bad indicators.

---

## 1. DNS

### Resolution chain

```
Client → Local cache → Hosts file → Recursive resolver (configured DNS server)
  → Root servers → TLD servers → Authoritative server → Response
```

### Detection-relevant DNS behaviours

| Behaviour | Normal | Suspicious | Detection signal |
|---|---|---|---|
| **Query length** | Subdomain < 30 chars | Subdomain > 50 chars | DNS tunnelling (data encoded in subdomain) |
| **Query frequency** | Varies by application | Regular intervals (beaconing) | Consistent inter-query intervals to same domain |
| **Query type** | A, AAAA, CNAME, MX | TXT, NULL, CNAME with long values | Data exfiltration via DNS (TXT records carry arbitrary data) |
| **Unique subdomains** | Low per domain | Hundreds of unique subdomains per domain | DNS tunnelling or DGA |
| **Response size** | Typically < 512 bytes | Large TXT responses | Data infiltration via DNS |
| **NXDOMAIN rate** | Low | High NXDOMAIN rate to one domain | DGA (Domain Generation Algorithm) |
| **Direct-to-IP DNS** | Queries go to configured resolver | Queries to 8.8.8.8, 1.1.1.1 directly | DNS resolver bypass (evading enterprise DNS monitoring) |

### DNS tunnelling mechanics

Data is encoded in DNS queries (subdomains) and responses (TXT/CNAME records). Tools: `iodine`, `dnscat2`, `dns2tcp`, Cobalt Strike DNS beacon.

**Encoding schemes**: Base32 (subdomain-safe), Base64 (with modified alphabet), hex. Detection: high entropy in subdomain labels, character distribution analysis (consonant ratio > 0.7 + length > 10).

### DGA detection

DGA domains have statistical properties that distinguish them from legitimate domains:
- High consonant-to-vowel ratio
- High digit ratio
- Uniform character distribution (high entropy)
- Length anomalies (very long or very short second-level domains)

**Anti-pattern**: Detecting DGA by domain length alone fails — CDN domains (`d2gj3xnhw63r7t.cloudfront.net`) are legitimately long. Use character distribution analysis.

---

## 2. TLS/HTTPS

### TLS handshake

```
Client → ClientHello (supported ciphers, SNI, extensions)
  → Server → ServerHello (selected cipher, certificate)
  → Client validates certificate chain
  → Key exchange → Encrypted session established
```

### Detection-relevant TLS behaviours

| Behaviour | Normal | Suspicious | Detection signal |
|---|---|---|---|
| **SNI mismatch** | SNI matches certificate CN/SAN | SNI doesn't match certificate | Domain fronting or misconfigured C2 |
| **Self-signed cert** | Trusted CA chain | Self-signed or unknown CA | C2 infrastructure, testing, or misconfiguration |
| **Certificate age** | Months to years | Hours to days (Let's Encrypt rapid issuance) | Freshly provisioned C2 infrastructure |
| **JA3/JA3S fingerprint** | Matches known browser/application | Matches known malware fingerprint | C2 tool identification |
| **Certificate transparency** | Certificate logged in CT logs | Certificate not in CT logs | Potentially malicious infrastructure |
| **Cipher suite** | Modern (TLS 1.2+, AEAD) | Legacy (TLS 1.0, RC4, export ciphers) | Downgrade attack or legacy malware |

### Domain fronting

Technique where the SNI (visible to network monitors) points to a legitimate CDN domain, but the HTTP `Host` header (encrypted) points to the actual C2 domain hosted on the same CDN.

**Detection**: Mismatch between SNI and HTTP Host header (requires TLS inspection), or statistical analysis of traffic patterns to CDN domains.

---

## 3. SMB (Server Message Block)

### SMB authentication

```
Client → SMB Negotiate → Server responds with supported dialects
  → Client → Session Setup (NTLM or Kerberos auth)
  → Tree Connect (access specific share)
  → File/pipe operations
```

### Detection-relevant SMB behaviours

| Behaviour | Detection signal | Event source |
|---|---|---|
| **Admin share access** (`C$`, `ADMIN$`, `IPC$`) | EID 5140/5145 with share name `\\*\C$` or `\\*\ADMIN$` | Security log |
| **Named pipe over SMB** | `IPC$` share + pipe name | EID 5145 with `RelativeTargetName` = pipe name |
| **PsExec pattern** | `ADMIN$` write + service creation + `IPC$` pipe | EID 5140 (ADMIN$) → 7045 (service) → 5140 (IPC$) |
| **NTLM relay via SMB** | SMB auth from unexpected source (machine account coercion) | EID 4624 Type 3 with unexpected source IP |
| **SMB lateral movement** | File copy to `ADMIN$` or `C$` followed by remote execution | Temporal correlation: file write → service/task creation |

### SMB coercion attacks

| Attack | Mechanism | Trigger | Detection |
|---|---|---|---|
| **PetitPotam** | EfsRpcOpenFileRaw forces NTLM auth | LSARPC named pipe | NTLM auth from DC machine account to unexpected target |
| **PrinterBug** | RpcRemoteFindFirstPrinterChangeNotification | Spooler service | NTLM auth from machine account to attacker-controlled host |
| **DFSCoerce** | NetrDfsRemoveStdRoot forces NTLM auth | DFS named pipe | Same pattern as PetitPotam |

---

## 4. HTTP/S C2 patterns

### Beaconing

C2 implants periodically check in with the C2 server. Detection relies on identifying regular communication patterns.

| Indicator | Normal web traffic | C2 beaconing |
|---|---|---|
| **Interval consistency** | Irregular (user-driven) | Regular intervals (± jitter) |
| **Jitter** | N/A | Low coefficient of variation (stdev/mean < 0.2) |
| **Data size** | Varies widely | Consistent small payloads (check-in) with occasional large (task/exfil) |
| **User-Agent** | Matches installed browser | Static UA, or UA that doesn't match OS |
| **URI patterns** | Varied paths | Repeated paths or predictable path patterns |
| **Time of day** | Business hours | 24/7 including off-hours |

### Domain fronting and CDN abuse

| Technique | Mechanism | Detection |
|---|---|---|
| **Domain fronting** | SNI = legitimate CDN, Host header = C2 | TLS inspection or traffic volume analysis |
| **CDN C2** | C2 hosted behind legitimate CDN (CloudFront, Azure CDN) | Unusual traffic patterns to CDN endpoints |
| **Redirector chains** | Multiple redirectors between implant and C2 | Redirect chain analysis, certificate chain analysis |

---

## 5. LDAP

### LDAP operations

| Operation | Purpose | Detection relevance |
|---|---|---|
| **Bind** | Authenticate to directory | Simple bind = cleartext password. NTLM bind = pass-the-hash possible. |
| **Search** | Query directory objects | Reconnaissance (user enumeration, SPN discovery, trust mapping) |
| **Modify** | Change object attributes | Privilege escalation (group membership, delegation attributes) |
| **Add** | Create new objects | Persistence (new accounts, new computer objects for RBCD) |

### LDAP reconnaissance detection

Volume and specificity of LDAP queries from a single source are the key signals. A workstation querying `(servicePrincipalName=*)` is Kerberoasting reconnaissance. A workstation querying `(objectClass=trustedDomain)` is trust enumeration.

---

## 6. RDP (Remote Desktop Protocol)

| Concept | Detail | Detection signal |
|---|---|---|
| **Standard RDP** | TCP 3389, TLS-encrypted | EID 4624 Type 10 (RemoteInteractive) |
| **NLA (Network Level Authentication)** | Kerberos/NTLM auth before session | EID 4624 before RDP session established |
| **RDP session hijacking** | `tscon.exe` to connect to another user's session | EID 4778 (session reconnected) without corresponding disconnect from original user |
| **Restricted Admin mode** | Pass-the-hash via RDP (no password sent to remote) | Logon Type 10 with NTLM auth (not Kerberos) |
| **Remote Credential Guard** | Kerberos tickets not sent to remote host | More secure but limits SSO on remote host |
| **SharpRDP** | RDP via API without mstsc.exe | RDP connection from non-mstsc process |

---

## 7. WinRM / PowerShell Remoting

```
Client → HTTP(S) on port 5985 (HTTP) or 5986 (HTTPS)
  → SOAP/WSMan protocol → PowerShell session on remote host
  → Commands execute as wsmprovhost.exe child of svchost.exe
```

**Detection signals**:
- EID 4624 Type 3 (Network) with `AuthenticationPackage` = Kerberos/NTLM
- Process creation: `wsmprovhost.exe` spawning child processes
- Network: connections to port 5985/5986
- PowerShell: EID 4104 (ScriptBlock) on the remote host showing executed commands

---

## 8. SMTP and email headers

### Email authentication chain

| Mechanism | What it validates | Header |
|---|---|---|
| **SPF** | Sending IP is authorised for the domain | `Received-SPF` or `Authentication-Results` |
| **DKIM** | Email content hasn't been modified | `DKIM-Signature` + `Authentication-Results` |
| **DMARC** | SPF and DKIM align with the From domain | `Authentication-Results` |

### Detection-relevant email header analysis

| Header | Detection use |
|---|---|
| `Received` (chain) | Trace email path. Forged headers appear before legitimate relay headers. |
| `X-Originating-IP` | Original sender IP (when present). Compare with SPF-authorised IPs. |
| `Return-Path` | Envelope sender. Mismatch with `From` = potential spoofing. |
| `Message-ID` | Unique identifier. Duplicate Message-IDs = replay. |
| `X-Mailer` / `User-Agent` | Email client. Unusual clients for the organisation = phishing infrastructure. |
| `Content-Type` | MIME type. `multipart/mixed` with executable attachments = high-risk. |

---

## 9. Telemetry sources per protocol

| Protocol | Primary log source | Windows Event IDs | Sysmon EIDs |
|---|---|---|---|
| DNS | DNS server logs, DNS client logs, proxy/firewall logs | — | 22 (DNSQuery) |
| TLS/HTTPS | Proxy/firewall logs, network tap/broker | — | 3 (NetworkConnect) |
| SMB | Windows Security log, file audit logs | 5140 (share access), 5145 (detailed share) | 3, 11, 17/18 |
| LDAP | Windows Security log (diagnostic logging) | 1644 (LDAP query, requires diagnostic flag) | — |
| RDP | Windows Security log | 4624 Type 10, 4778/4779 (session reconnect) | 3 (NetworkConnect) |
| WinRM | Windows Security log, PowerShell logs | 4624 Type 3, 4104 (ScriptBlock) | 3 |
| SMTP | Mail gateway logs, mail transfer agent logs | — | — |

> Map these log sources to your SIEM's tables/indexes. Consult the relevant platform skill (`microsoft-sentinel`, `splunk-spl-processing`, `crowdstrike-falcon`, etc.) for table names and ingestion specifics.

---

## 10. Quality checklist

- [ ] Detection targets protocol-level behaviour, not just known-bad IPs/domains.
- [ ] DNS detections use character distribution analysis, not just length thresholds.
- [ ] TLS detections consider certificate properties (age, CA, CT logging).
- [ ] SMB detections distinguish admin share access from normal file sharing.
- [ ] Beaconing detection uses statistical methods (coefficient of variation).
- [ ] LDAP reconnaissance detection correlates query specificity with source privilege.
- [ ] RDP detections distinguish standard logon from session hijacking.
- [ ] Email header analysis validates SPF/DKIM/DMARC alignment.
- [ ] Protocol-specific telemetry sources identified per detection platform.
- [ ] Coercion attacks (PetitPotam, PrinterBug) considered for NTLM relay detections.
