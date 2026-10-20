# Splunk SPL Anti-Patterns (AP-S1 — AP-S12)

Common anti-patterns in SPL query design for Splunk Enterprise / Enterprise Security. Use as a rejection checklist.

---

## AP-S1: The Indexless Search

**Pattern**: No `index=` constraint — scans any index defined as default.

```spl
// BAD
sourcetype="WinEventLog:Security" EventCode=4688

// GOOD
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
```

**Why it fails**: Without `index=`, Splunk scans all indexes defined as default. On a multi-TB deployment, no default index is defined; therefore in the absence of `index=` nothing is returned (nothing is searched).

---

## AP-S2: The Timeless Search

**Pattern**: No `earliest=` / `latest=` time bound.

```spl
// BAD
index=wineventlog EventCode=4625

// GOOD
index=wineventlog EventCode=4625 earliest=-7d@d latest=now
```

**Why it fails**: Unbounded searches scan the default search window (e.g. last 24 hours). Always include time bounds justified in the rationale if not defined in the Splunk section of the YAML file.

---

## AP-S3: The Incomplete Base Search

**Pattern**: Filtering conditions that could be applied in the initial search expression are instead deferred to subsequent `eval`/`where` commands after the pipe, forcing Splunk to retrieve and parse far more events than necessary.

```spl
// BAD: EventCode filter is present but CommandLine condition is split across
// multiple eval/where steps instead of being part of the base search
index=wineventlog EventCode=4688 earliest=-7d@d
| eval CmdLower=lower(CommandLine)
| where like(CmdLower, "%-encodedcommand%")
| eval ParentLower=lower(ParentImage)
| where like(ParentLower, "%\\mshta.exe")
| stats count by host, CommandLine

// GOOD: push as many conditions as possible into the base search expression
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688 earliest=-7d@d
    CommandLine="*-encodedcommand*" ParentImage="*\\mshta.exe"
| stats count by host, CommandLine
```

**Why it fails**: Conditions in the base search expression (before the first pipe) are applied at the indexer level during the initial event retrieval phase. When equivalent conditions are expressed as `eval`/`where` after the pipe, every matching event must first be retrieved and parsed before the filter applies. Moving known filtering criteria into the base search drastically reduces the event volume entering the pipeline.

---

## AP-S4: The Subsearch Bomb

**Pattern**: Subsearch returning too many results (default cap: 10,000 results, 60 seconds).

```spl
// BAD: subsearch may hit the 10k cap silently
index=proxy [search index=threat_intel | fields indicator]

// GOOD: lookup against a pre-loaded IOC feed
index=proxy earliest=-24h
| lookup threat_intel_feed indicator AS dest_ip OUTPUT category, severity
| where isnotnull(category)

// GOOD: inputlookup for tenant-maintained IOC tables
index=proxy earliest=-24h
| lookup local=t ioc_ip_lookup ip AS dest_ip OUTPUT threat_name
| where isnotnull(threat_name)
```

**Why it fails**: Subsearches have hard limits (10k results, 60s timeout). Exceeding them silently truncates results — the search appears to work but misses matches. The constraint on timeout cannot be changed. If the subsearch is needed, use command `format` or evaluate the special fields `search` or `query`.

---

## AP-S5: The Join Addiction

**Pattern**: Using `join` for correlation instead of `lookup`, `stats`, or data models.

```spl
// BAD: join in SPL works with a sub-search
index=wineventlog EventCode=4624
| join type=inner host [search index=wineventlog EventCode=4688]

// GOOD: stats-based correlation
index=wineventlog (EventCode=4624 OR EventCode=4688) earliest=-1d@d
| stats values(EventCode) AS events dc(EventCode) AS event_types by host, user
| where event_types >= 2
```

**Why it fails**: `join` works with a sub-search that runs before the main search. The sub-search conditions are not refined to limit to the values found on the main search. The command `join` should be banned.

---

## AP-S6: The stats-When-tstats-Works

**Pattern**: Using `stats` against raw events when `tstats` against an accelerated data model or against raw logs with TERM() and/or PREFIX() would be 10-100x faster.

```spl
// BAD: full event scan
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
| stats count by host, user

// GOOD: accelerated data model
| tstats summariesonly=true count from datamodel=Endpoint.Processes
    where Processes.action=allowed
    by Processes.dest, Processes.user

// GOOD: raw logs
// Search example. The URI is a TERM() literal inside the query, not a request this skill makes.
| tstats count 
    where index=proxy TERM(uri=http://www.example.com/*)
    by PREFIX(r_ip=) 
```

**Why it fails**: `tstats` reads from pre-built tsidx summaries without reading the buckets containing the raw logs. `stats` reads the tsidx summaries first and then each candidate bucket to parse every raw event. The performance difference is dramatic on large datasets.

**Caveat**: `summariesonly=true` only returns data from accelerated time ranges. Without it, Splunk falls back to raw events for unaccelerated periods.

---

## AP-S7: The Unthrottled Notable

**Pattern**: ES correlation search with no throttling — generates duplicate notables for the same entity.

```spl
// BAD: fires a notable for every matching event
... | sendalert notable

// GOOD: throttle by entity
... | sendalert notable
// Throttling: fields="user,src" duration="1h"
```

**Why it fails**: Without throttling, a brute-force attack generating 1000 events creates 1000 notables. Analysts drown. Always set throttling fields that define alert uniqueness.

---

## AP-S8: The Unbounded Multi-Value Fields

**Pattern**: `values()` or `list()` without size limits on high-cardinality fields.

```spl
// BAD: an IP with 50k+ users yields gigabytes
| stats values(user) AS all_users by src_ip
 
// GOOD: limit and count separately
| stats values(user) AS user_sample dc(user) AS user_count by src_ip
| where user_count > 10
```

**Why it fails**: `values()` collects every distinct value. On high-cardinality fields this consumes excessive memory and produces unreadable results.

---

## AP-S9: The Unindexed Field Search

**Pattern**: Searching based on `_time` rather than `_index_earliest`/`_index_latest`. On Splunk, it is common for events to be indexed long after they were generated (e.g. Windows Event Logs collected from remote devices could be indexed days later when they reconnect to the log collection pipeline).

```spl
// BAD: search based on _time — misses late-arriving events
index=wineventlog CommandLine="*mimikatz*" TERM(mimikatz) earliest=-70m latest=-10m

// GOOD: ensure all events are searched when indexed
index=wineventlog CommandLine="*mimikatz*" TERM(mimikatz) _index_earliest=-70m _index_latest=-10m earliest=-60d
```

**Why it fails**: If events enter the pipeline long after they are generated and `_time` is set to the generation time, scheduled searches (detections) based on `_time` will miss the event entirely (never processed).

---

## AP-S10: The Risk Score Without Rationale

**Pattern**: RBA risk scores assigned without documented justification.

```spl
// BAD: why 40? why not 20 or 80?
| eval risk_score=40

// GOOD: documented rationale
| eval risk_score=40
``` ``` Risk score 40: Medium-confidence behavioural signal. Threshold for
    notable creation is 100 per entity per 24h. Two of these signals
    from the same user within 24h will trigger investigation. ```
```

**Why it fails**: Arbitrary scores make RBA untunable. Document the scoring rationale so analysts and tuning engineers can adjust thresholds.

---

## AP-S11: The CIM Field Assumption

**Pattern**: Using CIM field names without verifying the sourcetype is CIM-compliant to the data model. Check whether the data model is accelerated or not.

```spl
// BAD: assumes CIM normalisation exists
| tstats count
    from datamodel=Authentication
    where Authentication.action=failure
    by Authentication.user, Authentication.src

// GOOD: verify first, document requirement
``` Requires: Authentication data model accelerated.
    Sourcetypes mapped: WinEventLog:Security (via TA-windows). ```
| tstats summariesonly=true count
    from datamodel=Authentication
    where Authentication.action=failure
    by Authentication.user, Authentication.src

// ACCEPTABLE: if the DM is not accelerated
| tstats count
    from datamodel=Authentication
    where Authentication.action=failure
    by Authentication.user, Authentication.src
```

**Why it fails**: CIM data models only work when sourcetypes are mapped via Technology Add-ons (TAs). Without this, `tstats` returns zero results — interpreted as "no threats" rather than "broken query". If possible, data models should be accelerated (use `summariesonly=true` then to benefit from acceleration).

---

## AP-S12: The Naked Leading Wildcard

**Pattern**: Using a leading wildcard (`*value`) in the base search without a complementary `TERM()` or `PREFIX()` directive to anchor the tsidx lookup.

```spl
// BAD: leading wildcard forces a full scan of every event in the index —
// Splunk cannot use the tsidx to narrow candidates
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    CommandLine="*\\mshta.exe"

// GOOD: complement the leading wildcard with TERM() on a known token
// that MUST appear in the same event, allowing tsidx pre-filtering
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    TERM(mshta) TERM(exe) CommandLine="*\\mshta.exe"
```

**Why it fails**: The tsidx (time-series index) stores segmented tokens — it can resolve trailing wildcards (`value*`) efficiently via prefix matching, but a leading wildcard (`*value`) requires scanning every event because no token prefix is known. When a leading wildcard is unavoidable (e.g. matching a path suffix like ``), pairing it with `TERM(mshta) AND TERM(exe)` gives Splunk a concrete token to look up in the tsidx first, drastically reducing the candidate set before the expensive wildcard match is applied. Caution: `TERM(mshta.exe)` does not work as `\\` is a minor breaker in the string "*\\mshta.exe", so there is no such string `mshta.exe` in TSIDX files — only the atomic strings `mshta` and `exe`.

**When TERM() applies**: `TERM()` matches a value delimited by major or minor breakers. The string within `TERM()` must be either the string between two breakers (minor or major) or the full string between two major breakers. For example, for the string `" example: www.example.com is a FQDN"`, `TERM(www)`, `TERM(example)`, `TERM(com)`, and `TERM(www.example.com)` are valid, while `TERM(www.example)` is not. When the beginning of the value is known, you can use `PREFIX()` in the `BY` clause.

```spl
// Another example: hunting for a specific DLL loaded from any path
// The leading wildcard is unavoidable — we don't know the full path
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7
    TERM(suspicious) TERM(dll) ImageLoaded="*\\suspicious.dll"
```

---

## Quick reference

| Red flag | Anti-pattern | Fix |
|---|---|---|
| No `index=` | AP-S1 | Always specify index |
| No `earliest=` | AP-S2 | Always specify time bounds |
| Filters after pipe instead of base search | AP-S3 | Push conditions into base search |
| Subsearch for large datasets | AP-S4 | Use `lookup` or `inputlookup` |
| `join` for correlation | AP-S5 | Use `stats`, `lookup`, or `tstats` |
| `stats` when DM is accelerated | AP-S6 | Use `tstats summariesonly=true` |
| No throttling on notables | AP-S7 | Set throttling fields + duration |
| Unbounded `values()` | AP-S8 | Limit or use `dc()` |
| `_time`-based scheduling for late events | AP-S9 | Use `_index_earliest`/`_index_latest` |
| Risk score without rationale | AP-S10 | Document scoring logic |
| CIM fields without DM verification | AP-S11 | Verify acceleration + TA mapping |
| Leading wildcard without `TERM()` | AP-S12 | Pair with `TERM()` or `PREFIX()` |
