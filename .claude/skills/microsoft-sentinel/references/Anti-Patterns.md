# Sentinel Query Anti-Patterns (AP-Q1 — AP-Q20)

A catalogue of common anti-patterns in KQL query design for Microsoft Sentinel. Use as a rejection checklist.

> **Hypothesis anti-patterns** (AP-H1–H5): see `kusto-query-language/references/Hypothesis-Anti-Patterns.md`.

---

## AP-Q1: The Dragnet

**Pattern**: Query so broad it returns thousands of results in any environment.

```kql
// BAD: catches every failed sign-in
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType != "0"
```

```kql
// GOOD: targets specific credential spray pattern
let proxy_ips = dynamic(["203.0.113.0/24"]);
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType in ("50126", "50053")
| where IPAddress in (proxy_ips)
| summarize FailCount = count(), DistinctUsers = dcount(UserPrincipalName)
    by IPAddress, bin(TimeGenerated, 1h)
| where FailCount > 50 and DistinctUsers > 10
```

---

## AP-Q2: The Copy-Paste

**Pattern**: Query copied from a blog/template without adaptation. Generic queries don't leverage the specific intelligence.

---

## AP-Q3: The Black Box

**Pattern**: No comments, no rationale. Hunters cannot trust queries they cannot understand.

**Fix**: Inline comments AND rationale field. Every non-trivial filter must be explained.

---

## AP-Q4: The Time Bomb

**Pattern**: No time bound or excessive lookback exceeding workspace retention.

```kql
// BAD: no time filter
AuditLogs | where OperationName == "Add member to role"

// GOOD: justified window
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName == "Add member to role"
| extend InitiatedByUPN = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, InitiatedByUPN, OperationName
```

---

## AP-Q5: The Single-Signal

**Pattern**: Single high-FP indicator without correlation.

**Fix**: Layer filters from intelligence — sign-in anomaly + privilege change + timing.

---

## AP-Q6: The Phantom Table

**Pattern**: Table not present (data connector not configured). Common Sentinel examples:
- `DeviceProcessEvents` (Defender) instead of `SecurityEvent`.
- `Timestamp` instead of `TimeGenerated`.
- `SecurityEvent` queries without the Windows Security Events connector.

**Fix**: Confirm table availability before validating; otherwise document required data connectors.

---

## AP-Q7: The Invented Column

**Pattern**: Column doesn't exist in the target table. Sentinel tables differ both internally and from Defender.

```kql
// BAD: AccountUpn does NOT exist in SigninLogs (Defender column)
SigninLogs
| where TimeGenerated > ago(30d)
| where AccountUpn has "@example.com"
//        ^^^^^^^^^^^ FAILS
```

```kql
// GOOD: UserPrincipalName is the correct column in SigninLogs
SigninLogs
| where TimeGenerated > ago(30d)
| where UserPrincipalName has "@example.com"
```

**Common cross-platform traps**:

| Wrong (Defender column) | Correct (Sentinel column) | Table |
|---|---|---|
| `Timestamp` | `TimeGenerated` | All Sentinel tables |
| `AccountUpn` | `UserPrincipalName` | `SigninLogs` |
| `AccountName` | `TargetUserName` / `SubjectUserName` | `SecurityEvent` |
| `DeviceId` | `Computer` | `SecurityEvent` |
| `ProcessCommandLine` | `CommandLine` | `SecurityEvent` (4688) |
| `RemoteIP` | `IPAddress` | `SigninLogs` |
| `RemoteIP` | `CallerIpAddress` | `AzureActivity` |

**Fix**: Never write a column without first confirming it in the table reference.

---

## AP-Q8: The Invalid Negation

**Pattern**: `!has_any` / `!contains_any` — invalid syntax.

```kql
// BAD
| where Location !has_any (safe_countries)
// GOOD
| where not(Location has_any (safe_countries))
```

---

## AP-Q9: The Implicit Precedence

**Pattern**: `and` + `or` without parentheses.

```kql
// BAD
| where ResultType in ("50126", "50053")
    or Location !in (office_countries) and IPAddress in (proxy_ips)

// GOOD
| where ResultType in ("50126", "50053")
    or (Location !in (office_countries) and IPAddress in (proxy_ips))
```

**Rule**: All `and`-groups MUST be parenthesised when mixed with `or`.

---

## AP-Q10: The Ungrounded Aggregate

**Pattern**: Expensive `summarize` on millions of rows BEFORE selective filters.

```kql
// BAD
SigninLogs
| where TimeGenerated > ago(30d)
| summarize LoginCount = count() by UserPrincipalName, IPAddress
| where LoginCount > 100

// GOOD
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType != "0"
| where not(Location in (office_countries))
| summarize FailCount = count() by UserPrincipalName, IPAddress
| where FailCount > 100
```

---

## AP-Q11: The Uncommented Query

**Pattern**: No inline comments explaining intent or filter rationale.

**Fix**: Header block + comments on `let` variables + non-obvious `where` clauses + exclusions. **Quality gate** — uncommented queries are rejected.

---

## AP-Q12: The Undocumented False Positive

**Pattern**: Acknowledges FPs but provides no triage path.

```kql
// GOOD
// FP expectation: New employees during MFA enrollment generate failed sign-ins.
// Triage: Check Azure AD user creation date — if <7 days, likely onboarding.
SigninLogs
| where TimeGenerated > ago(14d)
| where ResultType in ("50126", "50053")
| join kind=leftanti (
    AuditLogs | where TimeGenerated > ago(7d) | where OperationName == "Add user"
    | extend NewUPN = tostring(TargetResources[0].userPrincipalName)
) on $left.UserPrincipalName == $right.NewUPN
| summarize FailureCount = count() by UserPrincipalName
| where FailureCount > 50
```

---

## AP-Q13: The Short-Term Filter

**Pattern**: `has` with terms ≤ 3 chars (not indexed).

```kql
// BAD: "GET" — full column scan
| where OperationNameValue has "GET"
// GOOD
| where OperationNameValue has "roleAssignments"
```

---

## AP-Q14: The Calculated Column Filter

**Pattern**: `extend`-computed column then filter on it.

```kql
// BAD
| extend LowerLocation = tolower(Location)
| where LowerLocation contains "china"
// GOOD
| where Location has "China"
```

---

## AP-Q15: The Assumed Causality

**Pattern**: Multi-table join without time-window validation.

```kql
// GOOD
SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == "0"
| where RiskLevelDuringSignIn in ("medium", "high")
| project LoginTime = TimeGenerated, UserPrincipalName, IPAddress
| join kind=inner (
    AuditLogs
    | where TimeGenerated > ago(30d)
    | where OperationName == "Add member to role"
    | extend InitiatedByUPN = tostring(InitiatedBy.user.userPrincipalName)
    | project RoleTime = TimeGenerated, InitiatedByUPN
) on $left.UserPrincipalName == $right.InitiatedByUPN
| where (RoleTime - LoginTime) between (0min .. 30min)
```

---

## AP-Q16: The Schema Assumption

**Pattern**: Assumes a column or data connector is always present.

```kql
// BAD: assumes RiskLevelDuringSignIn always populated
| where RiskLevelDuringSignIn == "high"
```

```kql
// GOOD
| extend RiskLevel = column_ifexists("RiskLevelDuringSignIn", "unknown")
| where RiskLevel == "high" or RiskLevel == "unknown"
```

**Why it fails**: Not all workspaces have Azure AD Identity Protection P2. Filtering on the column when it contains only "none" silently drops all results.

**Fix**: Use `column_ifexists()` for optional columns; document data-connector requirements in rationale.

---

## AP-Q17: UEBA as Primary Data Source

**Pattern**: Query starts from `BehaviorAnalytics` or `IdentityInfo` instead of raw telemetry.

```kql
// BAD: UEBA has incomplete coverage — misses unscored events
BehaviorAnalytics
| where InvestigationPriority > 5
| join kind=inner SigninLogs on ...

// GOOD: raw telemetry → UEBA enrichment via leftouter
SigninLogs
| where TimeGenerated > ago(14d)
| where /* detection filters */
| join kind=leftouter (
    BehaviorAnalytics | where isnotempty(SourceIPAddress)
) on $left.IPAddress == $right.SourceIPAddress
```

---

## AP-Q18: Unbounded `make_set`

**Pattern**: `make_set()` / `make_list()` without a size limit on high-cardinality columns.

```kql
// BAD: an IPAddress with 50k+ associated users yields gigabytes
| summarize AllUsers = make_set(UserPrincipalName) by IPAddress

// GOOD
| summarize UserSample = make_set(UserPrincipalName, 100) by IPAddress
```

**Fix**: Always specify the second argument. Use `dcount()` alongside for the actual count.

---

## AP-Q19: `union isfuzzy=true` as Default

**Pattern**: Using `isfuzzy=true` when both tables are standard and known to share schemas.

```kql
// BAD: masks schema mismatches and missing tables silently
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
```

**When `isfuzzy=true` IS appropriate**: tables that may not exist in all environments (e.g. custom logs with schema drift across versions).

---

## AP-Q20: DGA Detection by Length Alone

**Pattern**: Flagging long domains as DGA without character-distribution analysis.

```kql
// BAD: CDNs and cloud domains routinely exceed 40 chars
| where strlen(DomainName) > 40

// GOOD
| extend SLD = tostring(split(DomainName, ".")[array_length(split(DomainName, ".")) - 2])
| extend ConsonantRatio = countof(SLD, "[bcdfghjklmnpqrstvwxyz]", "regex") * 1.0 / strlen(SLD)
| extend DigitRatio = countof(SLD, "[0-9]", "regex") * 1.0 / strlen(SLD)
| where (ConsonantRatio > 0.7 and strlen(SLD) > 10)
    or (DigitRatio > 0.3 and strlen(SLD) > 8)
```

Legitimate domains like `d2gj3xnhw63r7t.cloudfront.net` exceed any length threshold. Use distribution analysis.

---

## Quick reference

| Red flag | Anti-pattern | Action |
|---|---|---|
| Expected results > 1000 in clean env | AP-Q1 | Add intel filters |
| No inline comments | AP-Q3 / AP-Q11 | Add comments + rationale |
| No `TimeGenerated` filter | AP-Q4 | Add justified bound |
| Single high-FP `where` | AP-Q5 | Add correlation |
| `Timestamp` / Defender columns | AP-Q7 | Switch to Sentinel column |
| `!has_any` / `!contains_any` | AP-Q8 | Use `not(...)` |
| `and` + `or` without parens | AP-Q9 | Parenthesise |
| `summarize` before filters | AP-Q10 | Filter first |
| "May return FPs" no triage | AP-Q12 | Add triage steps |
| `has` with ≤ 3 char term | AP-Q13 | Use exact match |
| Filter on `extend` column | AP-Q14 | Filter raw column |
| Join without time window | AP-Q15 | Add `between` |
| Assumes optional column | AP-Q16 | `column_ifexists()` |
| `BehaviorAnalytics` as base | AP-Q17 | Leftouter join from raw |
| `make_set()` no limit | AP-Q18 | Add max size |
| `isfuzzy=true` on standard tables | AP-Q19 | Explicit `union` |
| DGA by length alone | AP-Q20 | Character distribution |
