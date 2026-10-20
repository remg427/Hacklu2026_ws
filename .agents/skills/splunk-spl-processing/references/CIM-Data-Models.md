# CIM data model catalogue

The Common Information Model (CIM) normalises data across sources. `tstats` against accelerated CIM data models is 10–100× faster than raw search.

**Before authoring**: verify acceleration in ES → Settings → Data Models. Unaccelerated models force raw-event fallback even with `summariesonly=true` on unaccelerated time ranges.

## Model catalogue

| Data model | Node | Detection use | Example fields | TA prerequisites |
|---|---|---|---|---|
| `Endpoint` | `Processes` | Process execution, command-line, LOLBAS | `process_name`, `process`, `parent_process`, `dest`, `user` | Splunk TA for Microsoft Windows, Sysmon, or endpoint EDR sourcetypes mapped to `Processes` |
| `Endpoint` | `Registry` | Registry modifications, persistence | `registry_path`, `registry_value_data`, `dest` | Windows / Sysmon TA with registry event types |
| `Endpoint` | `Filesystem` | File creation/deletion, ransomware | `file_name`, `file_path`, `action`, `dest` | Windows / Sysmon / EDR TA |
| `Endpoint` | `Services` | Service installation, persistence | `service_name`, `start_mode`, `dest` | Windows TA (Event 7045, 4697) |
| `Network_Traffic` | `All_Traffic` | Port scans, lateral movement, C2 | `src`, `dest`, `dest_port`, `transport`, `action` | Network TA (firewall, Zeek, Cisco ASA) |
| `Network_Resolution` | (DNS) | DNS exfiltration, DGA | `query`, `answer`, `query_type`, `src` | DNS TA (BIND, Infoblox, MS DNS) |
| `Web` | (default) | Web attacks, SQLi, webshells | `url`, `http_method`, `status`, `src`, `dest` | Web proxy / WAF TA (Squid, IIS, Apache) |
| `Authentication` | (default) | Logon events, brute force | `user`, `src`, `dest`, `action`, `app` | Windows Security, VPN, IdP sourcetypes |
| `Change` | `All_Changes` | Account/config changes | `user`, `object`, `action`, `command` | Windows / AD / cloud audit sourcetypes |
| `Risk` | `All_Risk` | RBA correlation | `risk_object`, `risk_score`, `source`, `annotations` | ES Risk Framework (populated by correlation searches) |

## Acceleration verification procedure

1. ES → Settings → Data Models → select target model → confirm **Acceleration** enabled.
2. Note accelerated time range (typically matches index retention).
3. Run a smoke test:

```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes earliest=-1h
```

4. Zero results with known process activity → check sourcetype→CIM mapping in ES → Data Inputs / TA configuration, not "no threats".

## ESCU / opentide macro mapping

| Purpose | ESCU macro | opentide equivalent (when deployed) |
|---|---|---|
| Summariesonly flag | `` `security_content_summariesonly` `` | `` `soc_macro_summariesonly` `` |
| Strip DM prefix | `` `drop_dm_object_name(Processes)` `` | Same pattern — tenant-defined |
| Epoch → readable time | `` `security_content_ctime(field)` `` | `` `soc_macro_ctime_utc(field)` `` |
| FP exclusions (Layer 3) | `` `<detection_name>_filter` `` | Tenant filter macro per rule |

Non-ESCU tenants: replace ESCU macros with tenant Layer 1/2/3 macros; never assume `security_content_*` exists.
