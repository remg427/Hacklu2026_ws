# Sentinel Multi-Query Correlation Patterns

Worked correlation queries for Microsoft Sentinel (Azure Log Analytics). Each pattern is a complete, runnable KQL block. Column names still defer to the tenant schema reference — see the column-authority rule in `SKILL.md`.

## Pattern 1 — Credential spray detection

```kql
// MITRE: T1110.003 (Password Spraying)
let lookback = ago(14d);
let spray_threshold = 50;
SigninLogs
| where TimeGenerated > lookback
| where ResultType in ("50126", "50053")
| summarize
    FailCount = count(),
    DistinctUsers = dcount(UserPrincipalName),
    DistinctLocations = dcount(Location),
    UserList = make_set(UserPrincipalName, 10)
    by IPAddress, bin(TimeGenerated, 1h)
| where FailCount > spray_threshold and DistinctUsers > 5
```

## Pattern 2 — Risky sign-in → privilege escalation

```kql
// MITRE: T1078 → T1098 chain
let lookback = ago(14d);
let risky_logins =
    SigninLogs
    | where TimeGenerated > lookback
    | where ResultType == "0"
    | where RiskLevelDuringSignIn in ("medium", "high")
    | project LoginTime = TimeGenerated, UserPrincipalName, IPAddress, RiskLevelDuringSignIn;
let role_changes =
    AuditLogs
    | where TimeGenerated > lookback
    | where OperationName == "Add member to role"
    | extend InitiatedByUPN = tostring(InitiatedBy.user.userPrincipalName)
    | project RoleTime = TimeGenerated, InitiatedByUPN,
        TargetRole = tostring(TargetResources[0].displayName);
risky_logins
| join kind=inner role_changes on $left.UserPrincipalName == $right.InitiatedByUPN
| where (RoleTime - LoginTime) between (0min .. 30min)
```

## Pattern 3 — New OAuth consent vs baseline

```kql
// MITRE: T1098.003 (Additional Cloud Credentials)
let baseline_apps = toscalar(
    AuditLogs
    | where TimeGenerated between (ago(90d) .. ago(30d))
    | where OperationName == "Consent to application"
    | extend AppName = tostring(TargetResources[0].displayName)
    | summarize make_set(AppName)
);
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Consent to application"
| extend AppName = tostring(TargetResources[0].displayName)
| extend ConsentUser = tostring(InitiatedBy.user.userPrincipalName)
| where not(AppName in (baseline_apps))
```

## Pattern 4 — Sign-in + Azure resource correlation

```kql
// MITRE: T1078 → T1578 chain
let lookback = ago(7d);
let suspicious_logins =
    SigninLogs
    | where TimeGenerated > lookback
    | where ResultType == "0"
    | where not(Location in ("<expected-locations>"))
    | project LoginTime = TimeGenerated, UserPrincipalName, IPAddress, Location;
let resource_ops =
    AzureActivity
    | where TimeGenerated > lookback
    | where OperationNameValue has "write"
    | where ActivityStatusValue == "Success"
    | project OpTime = TimeGenerated, Caller, OperationNameValue, ResourceGroup;
suspicious_logins
| join kind=inner resource_ops on $left.UserPrincipalName == $right.Caller
| where (OpTime - LoginTime) between (0min .. 120min)
```

## Pattern 5 — Beaconing via network appliance logs

```kql
// MITRE: T1071.001 (Application Layer Protocol: Web)
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DestinationPort in (443, 80, 8443)
| summarize
    ConnectionTimes = make_list(TimeGenerated),
    ConnectionCount = count(),
    TotalBytes = sum(SentBytes)
    by SourceIP, DestinationIP, DestinationPort
| where ConnectionCount > 20
| extend SortedTimes = array_sort_asc(ConnectionTimes)
| mv-apply SortedTimes on (
    extend PrevTime = prev(SortedTimes, 1)
    | where isnotempty(PrevTime)
    | extend IntervalSeconds = datetime_diff('second', SortedTimes, PrevTime)
    | summarize AvgInterval = avg(IntervalSeconds), StdevInterval = stdev(IntervalSeconds)
)
| where StdevInterval / AvgInterval < 0.2  // low CV = consistent timing = beaconing
```

## Pattern 6 — Schema-variant union

```kql
// Combine SigninLogs + AADNonInteractiveUserSignInLogs (different schemas)
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d)
| where ResultType == "0"
| where Location in (suspicious_countries)
| extend
    ParsedLocation = parse_json(LocationDetails),
    ParsedDevice = parse_json(DeviceDetail)
| extend
    City = tostring(ParsedLocation.city),
    Browser = tostring(ParsedDevice.browser),
    OS = tostring(ParsedDevice.operatingSystem)
```

> `union isfuzzy=true` suppresses column-mismatch errors when unioning tables with different schemas.

## Pattern 7 — TI feed matching pipeline (`materialize` + `arg_max` + `coalesce`)

```kql
let lookback = ago(14d);
// Stage 1: dedup TI indicators (latest per indicator)
let active_ti = materialize(
    ThreatIntelligenceIndicator
    | where TimeGenerated > lookback
    | where ExpirationDateTime > now()
    | where Active == true
    | summarize arg_max(TimeGenerated, *) by IndicatorId
    | extend TI_IP = coalesce(NetworkIP, NetworkSourceIP, NetworkDestinationIP)
    | where isnotempty(TI_IP)
    | project TI_IP, Description, ThreatType, ConfidenceScore, IndicatorId
);
let signin_matches =
    SigninLogs
    | where TimeGenerated > lookback
    | where ResultType == "0"
    | join kind=inner active_ti on $left.IPAddress == $right.TI_IP
    | project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ThreatType, ConfidenceScore;
let network_matches =
    CommonSecurityLog
    | where TimeGenerated > lookback
    | join kind=inner active_ti on $left.DestinationIP == $right.TI_IP
    | project TimeGenerated, SourceIP, DestinationIP, DeviceVendor, ThreatType, ConfidenceScore;
union kind=outer signin_matches, network_matches
| order by ConfidenceScore desc, TimeGenerated desc
```

> `materialize()` is critical: TI dedup feeds multiple joins. Without it, the dedup runs once per join, wasting quota and risking timeouts.

## Pattern 8 — Session-window analysis

```kql
// Brute-force sessions clustered into attack windows
let session_gap = 5m;
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType != "0"
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, AppDisplayName
| sort by IPAddress asc, TimeGenerated asc
| extend SessionId = row_window_session(TimeGenerated, session_gap, session_gap)
| summarize
    SessionStart = min(TimeGenerated),
    SessionEnd = max(TimeGenerated),
    AttemptCount = count(),
    DistinctUsers = dcount(UserPrincipalName),
    UserList = make_set(UserPrincipalName, 10),
    ErrorCodes = make_set(ResultType)
    by IPAddress, SessionId
| where AttemptCount > 20 and DistinctUsers > 3
```

> `row_window_session()` creates dynamic sessions based on actual event gaps — far more accurate than fixed `bin(TimeGenerated, 1h)` windows that may split a single attack across boundaries.

## Pattern 9 — AiTM / BEC chain

```kql
// MITRE: T1557 → T1078 → T1114.003
let lookback = ago(7d);
let suspicious_sessions = materialize(
    SigninLogs
    | where TimeGenerated > lookback
    | where ResultType == "0"
    | where RiskLevelDuringSignIn in ("medium", "high")
        or column_ifexists("RiskState", "") == "atRisk"
    | where UserAgent has_any ("python", "axios", "node-fetch", "Go-http-client")
        or isempty(UserAgent)
    | project LoginTime = TimeGenerated, UserPrincipalName, IPAddress, SessionId = CorrelationId
);
let inbox_rules =
    OfficeActivity
    | where TimeGenerated > lookback
    | where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
    | where Parameters has_any ("DeleteMessage", "MoveToFolder", "ForwardTo", "RedirectTo")
    | project RuleTime = TimeGenerated, UserId, Operation, Parameters;
suspicious_sessions
| join kind=inner inbox_rules on $left.UserPrincipalName == $right.UserId
| where (RuleTime - LoginTime) between (0min .. 120min)
```

## Pattern 10 — Multi-technique union (identity)

```kql
// Detect any of multiple credential-compromise vectors
let lookback = ago(14d);
let spray =
    SigninLogs
    | where TimeGenerated > lookback
    | where ResultType in ("50126", "50053")
    | summarize FailCount = count(), Users = dcount(UserPrincipalName)
        by IPAddress, bin(TimeGenerated, 1h)
    | where FailCount > 50 and Users > 5
    | project TimeGenerated, Technique = "T1110.003-PasswordSpray",
        Entity = IPAddress, Detail = strcat(FailCount, " failures across ", Users, " users");
let mfa_fatigue =
    SigninLogs
    | where TimeGenerated > lookback
    | where ResultType == "500121"  // MFA denied
    | summarize DenialCount = count() by UserPrincipalName, bin(TimeGenerated, 30m)
    | where DenialCount > 5
    | project TimeGenerated, Technique = "T1621-MFAFatigue",
        Entity = UserPrincipalName, Detail = strcat(DenialCount, " MFA denials in 30min");
let legacy_auth =
    SigninLogs
    | where TimeGenerated > lookback
    | where ResultType == "0"
    | where ClientAppUsed !in ("Browser", "Mobile Apps and Desktop clients")
    | where ClientAppUsed has_any ("IMAP", "POP", "SMTP", "EAS")
    | project TimeGenerated, Technique = "T1078-LegacyAuth",
        Entity = UserPrincipalName, Detail = strcat("Legacy auth: ", ClientAppUsed);
union kind=outer spray, mfa_fatigue, legacy_auth
| order by TimeGenerated desc
```

---
