---
name: harfanglab
description: HarfangLab orb / EDR detection engineering — Sigma rule authoring in CoreTide's validated YAML schema (selections array, modifiers, conditional field validation), RHQL hunt query language, YARA file/memory scanning (CoreTide structure with imports, meta.context, auto-routing), full logsource category catalogue (39 Windows, 12 Linux, 6 macOS), 21 Sigma modifiers, maturity/confidence/action lifecycle, exclusion discipline, and SIEM ingestion patterns. Distilled from CoreTide HarfangLab sub-schema and SigmaHQ (3132 rules). Use for harfanglab-keyed configurations in opentide MDR objects.
---

# HarfangLab orb (EDR) — content authoring

This skill encodes operational context for content authoring against HarfangLab's EDR product (orb). HarfangLab is a French EDR vendor with strong Sigma support; rule authoring blends Sigma packs (vendor-curated and customer-authored) with the platform's native query language (RHQL — Realtime Hunting Query Language) for hunting.

---

## 1. Surface identification

| Surface | Purpose | Authoring expression |
|---|---|---|
| **Sigma rules** | Behavioural detection rule packs | Sigma YAML (HarfangLab tooling translates internally) |
| **Custom detection rules** | Customer-authored behavioural rules | Sigma YAML, optionally with RHQL extensions |
| **RHQL hunting** | Ad-hoc hunting queries | RHQL |
| **YARA rules** | File / memory pattern matching | Standard YARA |
| **Whitelists** | Exclusions for known-good behaviour | Path / hash / signer / process |
| **Threat Intel** | IOC ingestion | STIX / CSV / API |

The primary detection-authoring surface is **Sigma**. HarfangLab's posture leans heavily on the open Sigma standard, which is a significant differentiator from most other EDR vendors.

---

## 2. Sigma rules — CoreTide schema format

HarfangLab consumes Sigma-based detection rules. In opentide, these are authored using the **CoreTide HarfangLab sub-schema** — an improved, fully validated YAML format that deviates from standard Sigma in key ways.

### CoreTide vs standard Sigma — key differences

| Aspect | Standard Sigma | CoreTide HarfangLab schema |
|---|---|---|
| Detection block | Named YAML maps (`detection: selection: ...`) | `selections` array of `{name, field, modifiers, value}` objects |
| Field validation | None — any string accepted | **Conditional enums** — fields validated per product+category |
| Modifiers | Pipe syntax (`Image\|endswith`) | `modifiers` array on each selection object |
| Maturity | `status` (experimental/test/stable) | `maturity` (Experimental/Testing/Stable) + `confidence` (Weak/Moderate/Strong) |
| Action | `level` (informational/low/medium/high/critical) | `action` (Alert / Alert & Block / Alert, Block & Quarantine) |
| Schema version | None | `schema: harfanglab::1.0` |

### CoreTide Sigma rule structure

```yaml
harfanglab:
  schema: harfanglab::1.0
  status: PRODUCTION
  maturity: Stable
  confidence: Strong
  action: Alert
  tags:
    - attack.execution
    - attack.t1059.001

  sigma:
    logsource:
      product: windows
      category: process_creation
    selections:
      - name: ProcessMatch
        field: Image
        modifiers:
          - endswith
        value:
          - '\powershell.exe'
          - '\pwsh.exe'
      - name: CommandLineMatch
        field: CommandLine
        modifiers:
          - contains
        value:
          - '-EncodedCommand'
          - '-enc '
      - name: FilterLegitimate
        field: ParentImage
        modifiers:
          - endswith
        value:
          - '\ccmexec.exe'
    condition: (ProcessMatch and CommandLineMatch) and not FilterLegitimate
    false_positives:
      - Legitimate enterprise software-deployment tooling
```

### Maturity / confidence / action lifecycle

| Field | Values | Maps to |
|---|---|---|
| `maturity` | Experimental → Testing → Stable | HarfangLab `hl_status` |
| `confidence` | Weak → Moderate → Strong | HarfangLab `rule_confidence_override` |
| `action` | Alert / Alert & Block / Alert, Block & Quarantine | HarfangLab `global_state` |

**Rule**: New rules start at `maturity: Experimental`, `confidence: Weak`, `action: Alert`. Promote only after production validation.

### Modifier catalogue (21 modifiers)

| Modifier | Purpose | Example |
|---|---|---|
| `contains` | Substring match | `CommandLine` contains `-enc` |
| `startswith` | Prefix match | `Image` starts with `C:\Windows\` |
| `endswith` | Suffix match | `Image` ends with `\powershell.exe` |
| `re` | Regular expression | `CommandLine` matches regex pattern |
| `cased` | Case-sensitive (default is case-insensitive) | Exact case match |
| `all` | All values must match (AND instead of default OR) | All strings present |
| `cidr` | CIDR IP range match | `DestinationIp` in `10.0.0.0/8` |
| `base64` | Base64-encode value before matching | Detect encoded strings |
| `base64offset` | Base64 with all 3 offset variants | Catch any alignment |
| `wide` | UTF-16LE encoding (alias for `utf16le`) | Wide string matching |
| `utf16` / `utf16le` / `utf16be` | Unicode encoding variants | Encoded string detection |
| `windash` | Windows dash variants (`-`, `/`, `–`, `—`, `―`) | Catch all dash styles |
| `exists` | Check field existence (value: true/false) | Field presence check |
| `fieldref` | Reference another field's value | Cross-field comparison |
| `expand` | Expand placeholder values | Pipeline integration |
| `gt` / `gte` / `lt` / `lte` | Numeric comparisons | Threshold detection |

### Logsource category catalogue

Fields available for each selection depend on the `product` + `category` combination. The schema validates this — invalid fields are rejected.

**Windows** (39 categories):

| Category group | Categories |
|---|---|
| **Process** | `process_creation`, `process_access`, `process_duplicate_handle`, `process_tampered` |
| **Network** | `network_connection`, `network_dpi`, `network_close` |
| **File** | `file_create`, `file_read`, `file_write`, `file_rename`, `file_remove`, `file_shadowcopy`, `file_download` |
| **Registry** | `registry_event` |
| **Driver/Module** | `driver_load`, `library_event` |
| **Injection** | `remote_thread`, `injected_thread`, `raw_device_access`, `etwti_ntallocatevirtualmemory` |
| **Named pipes** | `named_pipe_creation`, `named_pipe_connection` |
| **PowerShell** | `powershell_event` |
| **AMSI** | `amsi_scan` |
| **Auth** | `login_event`, `logout_event` |
| **DNS** | `dns_query` |
| **URL** | `url_request` |
| **Account** | `user`, `group` |
| **System** | `service`, `scheduled_task`, `eventlog` |
| **Win32k** | `win32k_getasynckeystate`, `win32k_registerrawinputdevices`, `win32k_setwindowshookex` |

**Linux** (12 categories): `process_creation`, `process_ptrace`, `bpf_event`, `library_event`, `filesystem_event`, `network_connection`, `network_listen`, `network_rawsocket`, `login_event`, `logout_event`, `url_request`, `dns_query`

**macOS** (6 categories): `process_creation`, `library_event`, `filesystem_event`, `network_connection`, `login_event`, `logout_event`

### Sigma → CoreTide translation guide

When converting a standard SigmaHQ rule to CoreTide format:

1. **`logsource`** → keep `product` and `category`, drop `service` (not used in CoreTide schema)
2. **`detection` blocks** → convert each named block to a `selections` array item with `name`, `field`, `modifiers`, `value`
3. **Pipe modifiers** (`Image|endswith`) → split into `field: Image` + `modifiers: [endswith]`
4. **Multiple fields in one block** → create separate selection items per field
5. **`condition`** → keep the boolean expression, reference selection `name` values
6. **`level`** → map to `action` (informational/low → Alert, medium/high → Alert & Block, critical → Alert, Block & Quarantine)
7. **`status`** → map to `maturity` (experimental → Experimental, test → Testing, stable → Stable)
8. **`falsepositives`** → `false_positives` array
9. **`tags`** → keep ATT&CK format (`attack.t1059.001`), validated by regex pattern

---

## 3. RHQL — Realtime Hunting Query Language

RHQL is HarfangLab's native query DSL for hunting. Field-comparison + boolean composition, with pipeline operators reminiscent of SPL/KQL hybrids.

### Idiomatic patterns

```
process.image.path matches ".*\\powershell\\.exe$"
    and process.command_line contains "-EncodedCommand"
| group by host.name
```

| RHQL construct | Notes |
|---|---|
| `field == value` | Equality |
| `field matches "<regex>"` | Regex |
| `field contains "value"` | Substring |
| `field in ["a", "b"]` | Multi-value |
| `and`, `or`, `not` | Boolean (parenthesise mixes) |
| `| group by`, `| count`, `| sort` | Pipeline aggregation |

Confirm exact syntax against vendor documentation before authoring — RHQL evolves between versions.

### Worked RHQL patterns

**Encoded PowerShell execution:**
```
process.image.path matches ".*\\\\powershell\\.exe$"
    and process.command_line contains "-EncodedCommand"
    and not process.parent.image.path matches ".*\\\\ccmexec\\.exe$"
| group by host.name, process.user
```

**LSASS access (credential dumping):**
```
process.target.image.path matches ".*\\\\lsass\\.exe$"
    and process.access.granted_access contains "0x1010"
    and not process.image.path matches ".*\\\\(MsMpEng|csrss|svchost)\\.exe$"
```

**Suspicious service creation:**
```
event.type == "service_creation"
    and (service.image_path contains "cmd.exe"
        or service.image_path contains "powershell.exe")
| group by host.name, service.name
```

**DNS to suspicious TLD:**
```
dns.query matches ".*\\.(top|xyz|tk|ml|ga|cf|buzz)$"
    and not dns.query in ["known-good.xyz"]
| group by host.name, dns.query
| count
| sort -count
```

---

## 4. YARA — CoreTide schema format

HarfangLab supports YARA rules for file and memory scanning. In CoreTide, YARA rules use a structured YAML format (mutually exclusive with Sigma — a rule is either Sigma OR YARA).

### CoreTide YARA rule structure

```yaml
harfanglab:
  schema: harfanglab::1.0
  status: PRODUCTION
  maturity: Stable
  confidence: Strong
  action: Alert
  tags:
    - attack.execution
    - attack.t1059.001

  yara:
    imports:
      - pe
      - math
    meta:
      context:
        - file
        - memory
      os: Windows
      arch:
        - x64
      score: High
    strings: |
      $mz = "MZ" at 0
      $suspicious_api = "VirtualAlloc" ascii wide
      $shellcode_pattern = { 48 83 EC 28 48 8B 05 }
    condition: |
      $mz and ($suspicious_api or $shellcode_pattern) and
      math.entropy(0, filesize) > 7.0
```

### YARA imports (available modules)

| Module | Purpose | Key functions |
|---|---|---|
| `pe` | Windows PE analysis | `pe.machine`, `pe.imports()`, `pe.exports()`, `pe.entry_point`, `pe.rich_signature`, `pe.number_of_sections` |
| `dotnet` | .NET assembly analysis | `dotnet.is_dotnet`, `dotnet.module_name`, `dotnet.number_of_streams` |
| `elf` | Linux ELF analysis | `elf.type`, `elf.machine`, `elf.entry_point` (⚠️ performance impact) |
| `hash` | Cryptographic hashing | `hash.md5()`, `hash.sha256()`, `hash.crc32()` |
| `math` | Mathematical functions | `math.entropy()`, `math.mean()`, `math.serial_correlation()` |
| `time` | Timestamp comparison | `time.now()` |
| `string` | String manipulation | `string.to_int()`, `string.length()` |
| `macho` | macOS Mach-O analysis | `macho.file_type`, `macho.has_entitlement()` |

### Scan context and auto-routing

| `meta.context` | Description | Auto-routing |
|---|---|---|
| `process` | Scan process memory and executable images | — |
| `thread` | Scan thread context and memory regions | — |
| `memory` | Scan raw memory regions and buffers | — |
| `file` | Scan files on disk | Auto-routes: `file.pe` (Windows), `file.macho` (macOS), `file.elf` (Linux) |

### YARA authoring discipline

- **`meta.context`** must be set — determines where the rule scans.
- **`meta.os`** must be set — determines file context routing.
- **Anchor strings** with `at` / `in` where possible to reduce scan scope.
- **Avoid pure-string YARA** against high-volume telemetry — performance cost is real.
- **Use modules** (`pe`, `math`) for structural checks rather than brute-force string matching.
- **`imports`** must list every module referenced in `condition`.
- **`score`** auto-derives from `alert_severity` but can be overridden (Informational=10, Low=30, Medium=50, High=70, Critical=90).

---

## 5. Whitelists / exclusions

| Type | Scope |
|---|---|
| Path | Directory / executable allow |
| Hash | SHA256 allow |
| Signer | Certificate-based trust |
| Process | Allow specific executable interactions |
| Network | IP / domain / subnet allow |

Same discipline as other EDR platforms: tightest scope, audit metadata (ticket, owner, expiry), quarterly review.

Document **expected whitelist patterns** in the Sigma rule's `falsepositives` block so SOC engineers can manage allow-lists without retuning rules.

---

## 6. Sensor capability boundaries

| Capability | Windows | macOS | Linux |
|---|---|---|---|
| Process / file / network telemetry | Full | Full | Full |
| Registry | Full | n/a | n/a |
| DNS | Full | Full | Per kernel module |
| Memory protection | Full | Limited | Limited |
| YARA file / memory scanning | Full | Full | Full |
| Driver-level visibility | Full (Windows kernel) | n/a | n/a |

Document gaps in MDR `description` rather than assuming parity. Linux endpoint coverage depends on kernel module / eBPF availability.

---

## 7. SIEM ingestion patterns

> Table/index names are SIEM-specific. Consult your SIEM's HarfangLab integration documentation for exact configurations.

| HFL source | Telemetry type | Ingestion method | Notes |
|---|---|---|---|
| Alerts / Threats | Detection alerts (Sigma, YARA, vendor rules) | Syslog CEF / API polling | Primary alert source |
| Telemetry events | Process, file, network, registry, DNS events | API export or Syslog | Requires appropriate telemetry policy |
| Audit logs | Admin actions, policy changes | API polling | Always available |
| Threat Intelligence | IOC matches | STIX/TAXII feed or API | Requires TI configuration |

### Syslog / CEF forwarding

HarfangLab supports Syslog forwarding in CEF format for alerts. Configure in Administration → Integrations → Syslog.

### API-based ingestion

For richer data (full telemetry events, alert context), use the HarfangLab API. The `/api/data/alert/alert/Alert/` and `/api/data/telemetry/` endpoints provide structured JSON.

---

## 8. Entity identifier alignment

| Concept | HarfangLab | Microsoft Defender | CrowdStrike | SentinelOne |
|---|---|---|---|---|
| Host | `host.name`, `agent.id` | `DeviceId`, `DeviceName` | `aid`, `ComputerName` | `agent.uuid`, `endpoint.name` |
| User | `user.name` | `AccountName`, `AccountUpn` | `UserName` | `user.name` |
| Process | `process.id` (with `process.start_time` for stability) | `ProcessUniqueId` | `ContextProcessId_decimal` | `process.storyline.id` |
| Hash | `process.image.hash.sha256` | `SHA256` | `SHA256HashData` | `tgt.process.image.sha256` |

Cross-platform correlation at the SOAR / SIEM layer.

---

## 9. Mapping into opentide MDR

When HarfangLab content lives in `configurations.harfanglab`:

- **Identify the surface** (Sigma rule / RHQL hunt / YARA / Whitelist).
- **Sigma YAML** carried inline; logsource accuracy verified.
- **MITRE mapping** in `tags` + MDR `description`.
- **Sensor / OS coverage** declared.
- **Expected whitelist patterns** documented in `falsepositives`.
- Coordinate with `opentide-rule` for placement and `detection-engineering` for lifecycle.

---

## 10. Quality checklist

- [ ] Surface identified (Sigma / RHQL / YARA / Whitelist).
- [ ] CoreTide schema version set (`schema: harfanglab::1.0`).
- [ ] `maturity` / `confidence` / `action` lifecycle fields set deliberately.
- [ ] Sigma `logsource.product` + `logsource.category` valid for the target platform.
- [ ] Sigma `selections` use the CoreTide array format (`name`, `field`, `modifiers`, `value`).
- [ ] Sigma `field` values validated against the category's allowed field enum.
- [ ] Sigma `modifiers` chosen deliberately — avoid loose `contains` on high-volume fields.
- [ ] Sigma `condition` references selection `name` values correctly.
- [ ] `false_positives` populated with known FP scenarios.
- [ ] `tags` include ATT&CK technique IDs in Sigma format (`attack.t1059.001`).
- [ ] YARA `meta.context` and `meta.os` set — determines scan scope and routing.
- [ ] YARA `imports` lists every module referenced in `condition`.
- [ ] YARA strings anchored where possible (`at`, `in`) for performance.
- [ ] Sensor / OS coverage declared in MDR description.
- [ ] Whitelists carry audit metadata (ticket, owner, expiry).
- [ ] SIEM ingestion method documented (Syslog CEF / API).
