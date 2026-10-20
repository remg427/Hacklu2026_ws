# Detection type patterns

Different detection types have distinct SPL shapes. Typical ESCU corpus mix: TTP-heavy, with smaller shares for anomaly, hunting, correlation, and baseline builders.

All patterns below assume the canonical `tstats` + CIM pipeline from the main skill (§5). Append `` `<detection_name>_filter` `` for ESCU deployments.

## TTP — direct pattern matching

Highest confidence. Direct technique matching against CIM-normalised fields.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  FROM datamodel=Endpoint.Processes
  WHERE Processes.process_name=ntdsutil.exe Processes.process="*ac i ntds*"
  BY Processes.dest, Processes.user, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `ntdsutil_export_ntds_filter`
```

## Anomaly — statistical deviation

Uses `eventstats` + 3-sigma (or documented threshold) against a baseline computed in-search.

```spl
`wineventlog_security` EventCode=4776 TargetUserName!=*$ Status=0xC000006A
| bucket span=2m _time
| stats dc(TargetUserName) AS unique_accounts values(TargetUserName) as tried_accounts
  BY _time, Workstation
| eventstats avg(unique_accounts) as comp_avg, stdev(unique_accounts) as comp_std BY Workstation
| eval upperBound=(comp_avg+comp_std*3)
| eval isOutlier=if(unique_accounts > 10 AND unique_accounts >= upperBound, 1, 0)
| search isOutlier=1
```

## Hunting — broader filters, richer context

Lower confidence, higher volume. More output fields for analyst triage.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  FROM datamodel=Endpoint.Processes
  WHERE Processes.process="*-enc*" OR Processes.process="*-encodedcommand*"
  BY Processes.dest, Processes.user, Processes.process
| `drop_dm_object_name(Processes)`
| where match(process, "(?i)-(enc|encodedcommand)")
```

## Correlation (RBA) — risk aggregation

Aggregates risk events from the Risk data model. Field aliases must not contain dots.

```spl
| tstats `security_content_summariesonly` min(_time) as firstTime max(_time) as lastTime
  sum(All_Risk.calculated_risk_score) as risk_score
  count(All_Risk.calculated_risk_score) as risk_event_count
  values(All_Risk.annotations.mitre_attack.mitre_tactic_id) as mitre_tactic_id
  dc(source) as source_count
  FROM datamodel=Risk.All_Risk
  WHERE All_Risk.analyticstories="<Story Name>" All_Risk.risk_object_type="system"
  BY All_Risk.risk_object All_Risk.risk_object_type
| `drop_dm_object_name(All_Risk)`
| where source_count >= 5
```

## Baseline — lookup table builders

Not alerting — scheduled periodically to maintain historical state.

```spl
| tstats `security_content_summariesonly` span=1d count FROM datamodel=Endpoint.Services
  BY Services.service_name, Services.dest
| `drop_dm_object_name(Services)`
| inputlookup append=t previously_seen_running_windows_services
| stats min(firstTimeSeen) as firstTimeSeen by service_name, dest
| outputlookup previously_seen_running_windows_services
```
