# Splunk SPL best practices

Extended optimisation reference. Load when authoring complex correlation, subsearch-heavy, or metrics-index searches.

## TERM() and PREFIX()

`TERM()` matches a token delimited by major or minor breakers in the tsidx. Use to anchor leading-wildcard searches (see AP-S12 in `Anti-Patterns.md`).

```spl
// Leading wildcard unavoidable — anchor with TERM tokens
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    TERM(mshta) TERM(exe) CommandLine="*\\mshta.exe"
```

`PREFIX()` in `tstats` BY clauses narrows tsidx when the field prefix is known:

```spl
| tstats count where index=proxy TERM(malicious) by PREFIX(src_ip=)
```

**Caution**: `TERM(mshta.exe)` fails when `\\` is a minor breaker — use atomic tokens (`mshta`, `exe`).

## Subsearch limits and alternatives

Subsearches cap at **10,000 results** and **60 seconds** — truncation is silent.

| Pattern | When to use |
|---|---|
| `lookup` / `inputlookup` | Static or periodically refreshed IOC/reference data |
| `format` + subsearch | Small primary set feeding a dynamic OR clause |
| `stats` / `tstats` union | Same-index correlation across event types |
| Accelerated CIM DM | Cross-sourcetype correlation at scale |

```spl
// GOOD: lookup enrichment (IOC feed pre-loaded)
index=proxy earliest=-24h
| lookup threat_intel_feed indicator AS dest_ip OUTPUT category, severity
| where isnotnull(category)

// GOOD: inputlookup for small IOC sets
index=proxy earliest=-24h
| lookup local=t ioc_ip_lookup ip AS dest_ip OUTPUT threat_name
| where isnotnull(threat_name)

// ACCEPTABLE: format for small dynamic sets only
| map search="search index=proxy dest_ip=$ip$" maxsearches=100
```

## Summary indexing

For long lookback aggregations that would re-scan terabytes nightly:

```spl
// Schedule daily; collect rolled-up data into summary index
index=wineventlog earliest=-1d@d latest=@d
| stats dc(user) AS unique_users count AS event_count by host, sourcetype
| collect index=summary_endpoint sourcetype=daily_rollup
```

Detection searches then target the summary index instead of raw events.

## Late-arriving events (_index_earliest)

Windows Event Logs from remote laptops may index days after `_time`. Scheduled detections should pair event-time bounds with index-time bounds:

```spl
index=wineventlog CommandLine="*mimikatz*" TERM(mimikatz)
    _index_earliest=-70m _index_latest=-10m earliest=-60d
```

## mstats and metrics indexes

`mstats` queries **metrics indexes** (pre-aggregated numeric time series) via MCatalog — not event indexes.

```spl
| mstats avg(_value) WHERE index=metrics sourcetype=vmware.cpu
    AND metric_name=cpu.usage BY host span=5m
```

Use `mstats` when telemetry is already in metrics format (OTel, infrastructure monitoring). Use `tstats` for CIM event data models; use `stats` for raw events.

## Scheduled vs real-time correlation searches

| Mode | Constraints |
|---|---|
| **Scheduled** | Default for ES correlation. Set cron/frequency aligned to lookback (e.g. 15 min schedule, 20 min lookback). Supports `tstats`, summary indexes, heavy `stats`. |
| **Real-time** | Continuous window (typically 1–5 min). Avoid `join`, large subsearches, unbounded `values()`. Prefer streaming + `tstats` on hot accelerated ranges. |
| **Throttling** | Always configure — duplicate notables erode analyst trust. Match `throttling.fields` to entity keys in MDR schema. |

## _index_earliest scheduling discipline

Align correlation search schedule with `_index_earliest` when sourcetypes have known ingestion lag. Document lag assumptions in MDR `description` rationale.
