# Entra ID Detection Cheatsheet — KQL examples

> These examples use KQL (Sentinel). The **logic and field names are portable** — adapt the syntax to your SIEM (SPL for Splunk, EQL/ES|QL for Elastic, CQL for CrowdStrike NG-SIEM, etc.).

## Password spray (high-volume failed auth from single IP)

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType in ("50126", "50053", "50064")
| summarize FailCount = count(), DistinctUsers = dcount(UserPrincipalName) by IPAddress
| where DistinctUsers > 10 and FailCount > 50
```

## MFA fatigue (repeated denials then success)

```kql
let MFADenials = SigninLogs
    | where ResultType == "500121"
    | summarize DenialCount = count(), FirstDenial = min(TimeGenerated), LastDenial = max(TimeGenerated) by UserPrincipalName
    | where DenialCount >= 5;
let Successes = SigninLogs
    | where ResultType == "0";
MFADenials
| join kind=inner Successes on UserPrincipalName
| where TimeGenerated between (LastDenial .. (LastDenial + 30m))
```

## New inbox rule after risky sign-in (AiTM chain)

```kql
let RiskySignIns = SigninLogs
    | where column_ifexists("RiskLevelDuringSignIn", "none") in ("medium", "high")
    | where ResultType == "0"
    | project RiskyTime = TimeGenerated, UserPrincipalName, IPAddress;
OfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule")
| join kind=inner RiskySignIns on $left.UserId == $right.UserPrincipalName
| where TimeGenerated between (RiskyTime .. (RiskyTime + 1h))
```

## Suspicious OAuth consent grant

```kql
AuditLogs
| where OperationName == "Consent to application"
| extend AppName = tostring(TargetResources[0].displayName)
| extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend Perms = tostring(TargetResources[0].modifiedProperties)
| where Perms has_any ("Mail.ReadWrite", "Files.ReadWrite.All", "Directory.ReadWrite.All")
```

## Service principal credential addition (persistence)

```kql
AuditLogs
| where OperationName in ("Add service principal credentials", "Update application – Certificates and secrets management")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetApp = tostring(TargetResources[0].displayName)
```

## Cross-tenant anomaly (novel B2B access)

```kql
SigninLogs
| where HomeTenantId != ResourceTenantId
| where ResultType == "0"
| summarize FirstSeen = min(TimeGenerated), Count = count() by UserPrincipalName, HomeTenantId, AppDisplayName
| where FirstSeen > ago(7d)
```

## PIM activation for critical roles

```kql
AuditLogs
| where OperationName == "Add member to role completed (PIM activation)"
| extend ActivatedRole = tostring(TargetResources[0].displayName)
| extend ActivatedBy = tostring(InitiatedBy.user.userPrincipalName)
| where ActivatedRole in ("Global Administrator", "Privileged Role Administrator")
```

## Permanent role assignment (bypassing PIM)

```kql
AuditLogs
| where OperationName == "Add member to role"
| where Result == "success"
| extend RoleName = tostring(TargetResources[0].displayName)
| extend AssignedUser = tostring(TargetResources[0].userPrincipalName)
| extend AssignedBy = tostring(InitiatedBy.user.userPrincipalName)
```
