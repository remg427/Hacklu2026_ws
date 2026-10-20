---
name: splunk-spl-processing
description: >-
  Splunk Enterprise and Enterprise Security SPL authoring for detection engineering —
  index/sourcetype/time discipline, tstats/CIM acceleration, ESCU macro layers, ES
  correlation searches, notables, and RBA. Use when authoring or reviewing SPL,
  configurations.splunk MDR blocks, ES correlation searches, or translating KQL
  hypotheses to Splunk. Pair with detection-engineering and opentide-rule.
---

# Splunk SPL — detection engineering

Author and review SPL for Splunk Enterprise / Enterprise Security. The discipline here mirrors the rigour applied to KQL in `kusto-query-language` — filter early, structure deliberately, and document every assumption.

> **Pair with**: `windows-event-logs` (EventCode mapping), `detection-engineering` (hunt→rule lifecycle), `opentide-rule` (`configurations.splunk`), `kusto-query-language` (conceptual KQL translation).

> **Distilled from**: Analysis of 2009 production detections, 234 macros, and 104 lookups in the Splunk ESCU corpus `splunk/security_content` (v5.26+). Source citation only — this skill does not contact that project and does not read a credential.

---

## 1. Search-time discipline

### 1.1 Always lead with index, sourcetype, time

Splunk searches without an `index=` constraint scan default indexes — in production, there is often no default, so nothing is searched.

```spl
index=wineventlog sourcetype="WinEventLog:Security" earliest=-7d@d latest=now
```

| Construct | Use |
|---|---|
| `index=` | Primary partition — always include |
| `sourcetype=` | Schema-level filter |
| `host=`, `source=` | Index-time fields — fast |
| `earliest=` / `latest=` | Event-time bound — prefer snapped (`-7d@d`) |
| `_index_earliest` / `_index_latest` | Index-time bound — late-arriving WEL from remote hosts |

Full rejection checklist: `references/Anti-Patterns.md` (AP-S1, AP-S2).

### 1.2 Indexed vs search-time fields

**Index-time** (TSIDX — usable with `tstats`): metadata fields plus anything in `fields.conf`.

**Search-time**: everything else — extracted per event from `props.conf` / `transforms.conf`.

Filter on index-time fields first; defer search-time parsing to the last possible moment.

```spl
// GOOD
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688 TERM(encodedcommand) CommandLine="*-encodedcommand*"

// BAD
index=wineventlog EventCode=4688
| eval command=CommandLine
| where match(command, "-encodedcommand")
```

**Leading wildcards** (`*value`) cannot use tsidx alone — pair with `TERM()` or `PREFIX()` on known tokens (AP-S12). Example: `TERM(mshta) TERM(exe) CommandLine="*\\mshta.exe"`.

### 1.3 Streaming vs transforming commands

Streaming (`eval`, `where`, `rex`, `fields`) parallelises across indexers. Transforming (`stats`, `chart`, `timechart`, `dedup`) collects to the search head.

```spl
// GOOD: filter and project before stats
index=wineventlog EventCode=4688 TERM(encodedcommand) CommandLine="*-encodedcommand*"
| eval ParentName=lower(ParentImage)
| fields _time, host, User, CommandLine, ParentName
| stats count by host, ParentName
```

---

## 2. Schema authority — non-negotiable

> Index names, sourcetypes, and CIM field availability are **tenant-specific**. Never assume `index=wineventlog` or that CIM fields exist without verification.

**Procedure before authoring `tstats from datamodel=...`**:

1. Confirm sourcetype→CIM mapping via Technology Add-ons (TAs) in the target deployment.
2. Verify data model **acceleration** in ES → Settings → Data Models.
3. Smoke-test with `| tstats summariesonly=true count from datamodel=<Model> earliest=-1h`.
4. Zero results with known activity → broken mapping, not "no threats" (AP-S11).

For Windows `EventCode=` filters, cross-reference `windows-event-logs` — map Event IDs to tenant index/sourcetype via Layer 1 macros, not hardcoded indexes.

Load full CIM catalogue and TA prerequisites: `references/CIM-Data-Models.md`.

---

## 3. `stats` vs `tstats` vs `streamstats` vs `mstats`

| Command | Source | Speed | Use when |
|---|---|---|---|
| `stats` | Raw events | Slowest | Fields not in tsidx / DM |
| `tstats` | TSIDX or accelerated CIM DM | 10–100× faster | Index-time fields, `TERM()`, accelerated models |
| `streamstats` | Streaming state | Fast | Stateful per-event windows (beaconing, sequences) |
| `mstats` | Metrics indexes (MCatalog) | Fast for metrics | Pre-aggregated numeric time series — not event indexes |

```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes
    where Processes.process_name=powershell.exe
    by Processes.dest, Processes.user
```

Always pair `tstats` on accelerated data models with `summariesonly=true` — without it, Splunk falls back to raw events for unaccelerated ranges.

`mstats` details: `references/Best-Practices.md`.

---

## 4. Lookups, eventtypes, macros

### Lookups

```spl
... | lookup threat_intel_feed indicator AS src_ip OUTPUT category, severity
```

Prefer `lookup` / `inputlookup` over subsearches for IOC correlation (AP-S4).

### Three-layer macro architecture

Production frameworks (ESCU, opentide) use three layers for portability:

| Layer | Suffix | Purpose |
|---|---|---|
| 1 — Source | `_logs`, `_index` | Index/sourcetype abstraction (`win_security_logs`, `proxy_logs`) |
| 2 — Process | `process_*` | Binary matching with anti-evasion (`process_name` + `original_file_name`) |
| 3 — Filter | `<detection>_filter` | FP exclusions — empty by default (`search *`) |

**Principle**: detections are write-once, deploy-anywhere. Customers tune macros, not core SPL.

Tenant content repos may ship `references/macros.conf` — treat as authoritative override for Layer 1/2/3 definitions when present.

---

## 5. Canonical `tstats` + CIM pattern

Single canonical block — detection variants in `references/Detection-Type-Patterns.md`.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  FROM datamodel=Endpoint.Processes
  WHERE <filter_conditions>
  BY Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| <post_processing>
| `<detection_name>_filter`
```

ESCU vs opentide macro mapping: `references/CIM-Data-Models.md`.

---

## 6. Enterprise Security: correlation searches

### Lifecycle

1. Hunting search validated ad-hoc.
2. Saved as **scheduled** correlation search (typically 5–15 min, lookback aligned).
3. Adaptive Response: notable (`alert_action.notable`), risk boost (`alert_action.risk`), TTP annotation.
4. Tuning via thresholds, suppression, Layer 3 filter macros.
5. **RBA**: low-fidelity signals aggregate per-entity risk; notables for high-fidelity or cumulative threshold breach.

### Scheduled vs real-time constraints

| Mode | Guidance |
|---|---|
| Scheduled | Default. Supports heavy `tstats`, summary indexes, long lookback. Align cron to lookback + ingestion lag. |
| Real-time | Continuous window (1–5 min). Avoid `join`, large subsearches, unbounded `values()`. |
| Throttling | Mandatory on production rules — set entity fields (`user`, `src`, `dest`) and duration. |

### Notable and RBA field shaping

```spl
... | eval rule_name="Suspicious PowerShell Execution", severity=high, src=host, user=User, signature="T1059.001"
```

```spl
... | eval risk_message="Unusual login from impossible-travel pair",
       risk_object=user, risk_object_type="user", risk_score=40,
       threat_object=src_ip, threat_object_type="ip_address"
```

Detection type shapes (TTP, Anomaly, Hunting, Correlation, Baseline): `references/Detection-Type-Patterns.md`.

Common idioms (beaconing, impossible travel): `references/SPL-Idioms.md`.

---

## 7. False-positive engineering

Surface tuning knobs explicitly — align with Layer 3 filter macros for production, inline blocks for hunt iteration:

````spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688 earliest=-7d@d
| where match(CommandLine, "(?i)-(enc|encodedcommand)")
``` --- BEGIN ENVIRONMENT FILTERS (move to Layer 3 filter macro for production) --- ```
| where NOT match(user, "(?i)^svc_")
| where NOT match(host, "(?i)^SCAN-")
``` --- END ENVIRONMENT FILTERS --- ```
| stats count by host, User, CommandLine
````

**Production**: migrate exclusions to `` `<detection_name>_filter` `` macro. **Hunting**: inline filters acceptable with documented rationale.

---

## 8. IOC query templates

The blocks in this section are detection-query examples. They are not commands this skill runs. Strings such as download or invoke aliases are indicator text to match inside a decoded command line.

Replace index/sourcetype with tenant Layer 1 macros.

```spl
// IP address — lookup enrichment
`proxy_logs` earliest=-30d
| lookup threat_intel_feed indicator AS dest_ip OUTPUT category, severity
| where isnotnull(category)
| table _time, src_ip, dest_ip, category, url

// Domain — base search + match
`dns_logs` earliest=-30d
| where match(query, "(?i)(malicious-domain\.example|bad-domain\.example)")

// Hash — process or file events
`endpoint_logs` earliest=-30d
| where sha256 IN ("<sha256_1>", "<sha256_2>")
| table _time, dest, user, file_name, sha256, process

// Base64-encoded PowerShell pipeline
// Detection example: the match is an indicator in decoded command-line text, not a command to run
`win_security_logs` EventCode=4688 earliest=-14d
| where match(CommandLine, "(?i)(-enc|-encodedcommand|-e )")
| rex field=CommandLine "(?i)-e(?:nc|ncodedcommand)?\s+(?<EncodedBlock>[^\s]+)"
| eval DecodedCommand=`base64decode(EncodedBlock)`
| where isnotnull(DecodedCommand)
| where match(DecodedCommand, "(?i)(IWR|DownloadString|IEX)")
```

---

## 9. Rationale and precision/recall scoring

When SPL feeds hunt records or MDR `description`/`response.procedure`, the rationale must answer:

1. **Why these indexes/sourcetypes?** What captures the observable.
2. **Why these filters?** Map each filter to intelligence or behavioural reasoning.
3. **What the query does NOT cover.** Variants, evasion, scope exclusions.
4. **How results connect to the hypothesis.** What a true positive proves.

| Score | Precision (FP volume in clean env) | Recall risk |
|---|---|---|
| HIGH | < 10 results; filters trace to specific intel | Narrow filters; variants may evade |
| MEDIUM | 10–100; mix of specific + behavioural | Known patterns covered; novel variants may evade |
| LOW | > 100; broad behavioural pattern | Broad detection; harder to evade |

---

## 10. SPL vs KQL — conceptual translation

| KQL | SPL |
|---|---|
| `where TimeGenerated > ago(7d)` | `earliest=-7d@d` |
| `where Column has "value"` | `Column=*value*` or CIM tagged search |
| `where Column == "value"` | `Column="value"` |
| `where Column in (a,b,c)` | `Column IN (a, b, c)` |
| `summarize count() by X, bin(Time, 5m)` | `bin _time span=5m \| stats count by X, _time` |
| `summarize arg_max(Time, *) by Key` | `dedup Key sortby -_time` or `stats latest(*) by Key` |
| `join kind=inner` | Avoid — use `lookup`, `stats`, or accelerated DMs |
| `materialize()` | Summary indexing or `tstats from datamodel=...` |
| `parse_json()` | `spath` |
| `extend` | `eval` |
| `let var = ...` | Early `eval` or saved macro |
| Comments `//` | Triple-backtick block comments (see §11 below) |

**Mindset shift**: `join` in SPL is expensive at scale. Prefer `lookup`, union + `stats`, or accelerated CIM data models.

---

## 11. Comment discipline

Splunk inline comments use triple backticks:

````spl
``` Detection: Suspicious encoded PowerShell ```
``` Source: <reference> ```
``` MITRE: T1059.001 ```
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688 earliest=-7d@d
| where match(CommandLine, "(?i)-(enc|encodedcommand)")
| stats count by host, User, CommandLine
````

Apply the same header structure used in KQL (Hunt, Source, MITRE, Platform). Within opentide MDR objects, inline SPL headers may be reduced — metadata lives in MDR `description` and alert templates.

---

## 12. Quality checklist

### Universal

- [ ] `index=` and `sourcetype=` (or CIM tag / eventtype / Layer 1 `*_logs` macro) present.
- [ ] Time bound via `earliest=` / `latest=` (or `_index_earliest`/`_index_latest` for late-arriving data).
- [ ] Streaming commands precede transforming commands.
- [ ] `tstats` used when fields are in accelerated CIM DM or TSIDX; `summariesonly=true` on DM queries.
- [ ] `drop_dm_object_name()` applied after `tstats` BY clause.
- [ ] No `join` — replaced with lookup, union + `stats`, or accelerated DM.
- [ ] Layer 1 `*_logs` / `*_index` macros for index/sourcetype portability.
- [ ] Process matching uses `process_name` and `original_file_name` where applicable.
- [ ] Anomaly detections use `eventstats avg/stdev` + documented threshold.
- [ ] Suppression / throttling configured on correlation searches.
- [ ] Notable / RBA fidelity choice deliberate and documented.
- [ ] Detection type matches pattern in `references/Detection-Type-Patterns.md`.

### ESCU / opentide macro conventions

- [ ] `` `security_content_ctime()` `` (ESCU) or `` `soc_macro_ctime_utc()` `` (opentide) applied to first/last time fields.
- [ ] Layer 3 filter macro (`` `<detection_name>_filter` ``) appended as last pipe.
- [ ] Header comment block populated (or deferred to MDR metadata with rationale).

---

## 13. Mapping into opentide MDR

When SPL is wired into `configurations.splunk` in an opentide MDR object, coordinate with `opentide-rule` for schema fields:

| MDR field | SPL / ES alignment |
|---|---|
| `query` | SPL block scalar — follow this skill |
| `threshold` | Integer match count before alert |
| `throttling.fields` / `throttling.duration` | Entity dedup — mirror ES throttling |
| `scheduling.cron` / `frequency` / `lookback` | Align to ingestion lag and `_index_earliest` where needed |
| `notable.event.title` / `.description` | Splunk notable field substitution: a field name wrapped in dollar signs. Syntax example only — not an environment variable, and this skill does not read one. |
| `notable.drilldown.name` / `.search` | Secondary investigation search |
| `risk.risk_objects[]` | `field`, `type`, `score` — document score rationale (AP-S10) |
| `risk.threat_objects[]` | `field`, `type` (e.g. `ip`, `file_hash`) |

Description, tuning narrative, severity, and response procedure → MDR `description` and `response.*`. Hunt-to-rule conversion: `detection-engineering`.

---

## 14. Reference catalogues — load when…

| Need | File |
|---|---|
| CIM model fields, TA prerequisites, macro mapping | `references/CIM-Data-Models.md` |
| TTP / Anomaly / Hunting / RBA / Baseline shapes | `references/Detection-Type-Patterns.md` |
| Beaconing, impossible travel, rare-process | `references/SPL-Idioms.md` |
| `eval` / `stats` function lookup | `references/Eval-and-Stats-Functions.md` |
| TERM/PREFIX, subsearch limits, summary indexing, mstats, scheduling | `references/Best-Practices.md` |
| Rejection checklist AP-S1–S12 | `references/Anti-Patterns.md` |
