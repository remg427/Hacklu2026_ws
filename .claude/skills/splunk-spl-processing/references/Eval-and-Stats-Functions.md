# Eval and stats function reference

Key functions for detection engineering SPL.

## Eval functions

| Function | Purpose | Example |
|---|---|---|
| `if(cond, true, false)` | Conditional value | `eval severity=if(count>100, "high", "medium")` |
| `case(c1,v1, c2,v2, ...)` | Cascade-branch conditional | `eval category=case(port==22,"ssh", port==3389,"rdp", 1==1,"other")` |
| `coalesce(f1, f2, ...)` | First non-null value | `eval user=coalesce(TargetUserName, SubjectUserName)` |
| `match(field, regex)` | Regex match (boolean) | `where match(process, "(?i)mimikatz")` |
| `like(field, pattern)` | SQL-like match | `where like(CommandLine, "%-encodedcommand%")` |
| `cidrmatch(cidr, ip)` | CIDR range match | `where cidrmatch("10.0.0.0/8", src_ip)` |
| `mvfilter(expr)` | Filter multivalue field | `eval bad_ports=mvfilter(match(dest_port, "^(4444|5555)$"))` |
| `mvcount(field)` | Count multivalue entries | `where mvcount(dest_port) > 5` |
| `mvindex(field, start, end)` | Slice multivalue field | `eval first_value=mvindex(values, 0)` |
| `mvjoin(field, delim)` | Join multivalue to string | `eval port_list=mvjoin(dest_port, ",")` |
| `split(field, delim)` | String to multivalue | `eval parts=split(process, "\\")` |
| `replace(field, regex, repl)` | Regex replace | `eval clean=replace(url, "\?.*$", "")` |
| `substr(field, start, len)` | Substring extraction | `eval ext=substr(file_name, -4)` |
| `len(field)` | String length | `where len(CommandLine) > 500` |
| `tonumber(field, base)` | String to number | `eval hex_val=tonumber(Status, 16)` |
| `tostring(field, format)` | Number to string | `eval time_str=tostring(_time, "commas")` |
| `strftime(time, format)` | Epoch to formatted string | `eval date=strftime(_time, "%Y-%m-%d")` |
| `strptime(str, format)` | String to epoch | `eval epoch=strptime(timestamp, "%Y-%m-%dT%H:%M:%S")` |
| `relative_time(time, spec)` | Time arithmetic | `eval yesterday=relative_time(now(), "-1d@d")` |
| `now()` | Current epoch time | `eval age=now()-_time` |
| `lower(field)` / `upper(field)` | Case normalisation | `eval proc=lower(process_name)` |
| `urldecode(field)` | URL decode | `eval decoded=urldecode(url)` |
| `base64decode(field)` | Base64 decode (via macro) | `` eval decoded=`base64decode(encoded_field)` `` |
| `spath(field, path)` | JSON/XML extraction | `eval user=spath(_raw, "actor.alternateId")` |
| `json_extract(field, path)` | JSON field extraction | `eval val=json_extract(event_data, "$.CommandLine")` |

## Stats functions

| Function | Purpose | Notes |
|---|---|---|
| `count` | Event count | Most common |
| `dc(field)` | Distinct count | Lateral movement (dc of hosts), brute force (dc of users) |
| `values(field)` | Distinct values (sorted) | Context preservation — limit cardinality |
| `list(field)` | All values (unsorted, with dupes) | Raw enumeration |
| `earliest(field)` / `latest(field)` | First/last by `_time` | Timeline analysis |
| `first(field)` / `last(field)` | First/last in result order | Order-dependent |
| `sum(field)` / `avg(field)` | Arithmetic aggregation | Risk score totals, averages |
| `min(field)` / `max(field)` | Range bounds | Time windows (`min(_time)`, `max(_time)`) |
| `stdev(field)` / `var(field)` | Statistical dispersion | Anomaly detection (3-sigma) |
| `perc<N>(field)` | Percentile | `perc95(response_time)` for outlier detection |
| `mode(field)` / `median(field)` | Central tendency | Baseline establishment |
