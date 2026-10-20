# Common SPL idioms

All idioms require `index=` and time bounds in production searches. Replace placeholder indexes/sourcetypes with tenant Layer 1 macros.

## Top-N + percentage

```spl
index=<tenant_index> earliest=-7d@d
| stats count by user
| eventstats sum(count) AS total
| eval pct = round(count * 100.0 / total, 2)
| sort - count
```

## Beaconing detection (interval consistency)

```spl
index=proxy sourcetype=proxy_logs earliest=-7d@d
| sort 0 src, dest, dest_port, _time
| streamstats current=false last(_time) AS prev_time by src, dest, dest_port
| where isnotnull(prev_time)
| eval interval = _time - prev_time
| stats count AS conn_count avg(interval) AS mean_interval stdev(interval) AS stdev_interval
    by src, dest, dest_port
| where conn_count > 20
| eval cv = stdev_interval / mean_interval
| where cv < 0.2
```

## Impossible travel (per-user pairwise)

Requires authentication logs with `user` and `country` (or equivalent geo field) normalised to CIM or tenant schema.

```spl
index=authentication sourcetype=<auth_sourcetype> earliest=-7d@d
| sort 0 user, _time
| streamstats current=false last(_time) AS prev_time last(country) AS prev_country by user
| where country != prev_country
| eval delta_min = (_time - prev_time) / 60
| where delta_min > 0 AND delta_min < 60
```

## Rare-process per host (anomaly via dcount)

```spl
index=endpoint earliest=-7d@d
| stats dc(host) AS host_count by process_name
| where host_count <= 3
```
