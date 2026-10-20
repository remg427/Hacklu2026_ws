---
name: entra-id
description: Microsoft Entra ID (formerly Azure AD) — identity platform internals, telemetry, and attack detection. Covers the full Entra ID surface including sign-in logs (interactive, non-interactive, service principal, managed identity), audit logs, Identity Protection risk signals, Conditional Access evaluation, directory role management, OAuth/consent grants, PRT/token mechanics, cross-tenant B2B/B2C, and workload identities. Includes SKU gating (P1 vs P2), ResultType code catalogue, identity attack patterns (password spray, AiTM, MFA fatigue, token theft, OAuth abuse, Golden SAML), and entity alignment for cross-platform correlation. Use for any work involving Entra ID telemetry, identity-focused detection, or directory security posture. Pair with the relevant platform skill for query mechanics (microsoft-sentinel, splunk-spl-processing, crowdstrike-falcon, etc.).
---

# Microsoft Entra ID — identity platform & detection

This skill encodes the identity-platform tribal knowledge for **Microsoft Entra ID** (formerly Azure AD) — the central identity provider for Microsoft 365, Azure, and thousands of SaaS applications. It covers the platform's architecture, telemetry surfaces, security features, and attack detection patterns.

Use this skill when working with:
- **Authentication telemetry** — sign-in logs, audit logs, risk detections
- **Identity attacks** — password spray, AiTM, MFA fatigue, token theft, OAuth abuse
- **Directory security** — role assignments, Conditional Access, PIM, app registrations
- **Cross-tenant scenarios** — B2B guest access, cross-tenant synchronisation, external identities
- **Workload identities** — service principals, managed identities, federated credentials

> **Naming**: "Azure AD" was renamed to "Microsoft Entra ID" in July 2023. The diagnostic log categories retain the legacy names (`SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AuditLogs`). These names are used by Sentinel, but the same data is available in any SIEM via Event Hubs, Graph API, or diagnostic settings — field names and schemas are identical regardless of destination. This skill uses "Entra ID" for the product and the canonical log category names throughout.

---

## 0. Entra ID architecture overview

Entra ID is a **multi-tenant, cloud-based identity and access management service**. Every Microsoft 365 and Azure subscription has an Entra ID tenant. Key concepts:

| Concept | Description |
|---------|-------------|
| **Tenant** | A dedicated instance of Entra ID representing an organisation. Identified by a tenant ID (GUID) and one or more verified domains. |
| **User principal** | A human identity (`user@domain.com`). Can be a member or a guest (B2B). |
| **Service principal** | An application identity in a tenant. Created when an app registration is consented to or provisioned. |
| **Managed identity** | An Azure-managed service principal bound to an Azure resource (VM, Function, etc.). No credential management required. |
| **App registration** | The global definition of an application (multi-tenant). The service principal is the per-tenant instance. |
| **Directory roles** | Built-in or custom roles granting administrative permissions (Global Admin, Security Reader, etc.). |
| **Conditional Access** | Policy engine evaluating sign-in context (user, device, location, risk, app) to enforce access controls. |
| **Identity Protection** | Risk-based detection engine (P2) that scores sign-in risk and user risk. |
| **PIM (Privileged Identity Management)** | Just-in-time role activation for privileged roles (P2). |

### Entra ID log categories

These are the canonical diagnostic log categories emitted by Entra ID. The names below are used in Sentinel, but the **same schema and field names** apply when ingested into Splunk (via Event Hubs / Azure Monitor Add-on), CrowdStrike NG-SIEM, Elastic, or any other SIEM.

| Log category | What it captures | Licence | Ingestion path |
|-------------|-----------------|---------|----------------|
| `SigninLogs` | Interactive user sign-ins | Free (limited), P1, P2 | Diagnostic settings, Graph API |
| `NonInteractiveUserSignInLogs` | Token refreshes, background app activity, SSO | P1, P2 | Diagnostic settings |
| `ServicePrincipalSignInLogs` | Service principal (app) authentications | P1, P2 | Diagnostic settings |
| `ManagedIdentitySignInLogs` | Managed identity authentications | P1, P2 | Diagnostic settings |
| `AuditLogs` | Directory changes (user/group/role/app/policy CRUD) | Free, P1, P2 | Diagnostic settings, Graph API |
| `RiskyUsers` | User risk state and history | P2 | Graph API |
| `UserRiskEvents` | Individual risk detections | P2 | Graph API |
| `RiskyServicePrincipals` | Workload identity risk | P2 | Graph API |
| `ProvisioningLogs` | Cross-tenant sync, HR provisioning | P1, P2 | Diagnostic settings |
| `NetworkAccessTrafficLogs` | Global Secure Access (Entra Internet/Private Access) | Separate licence | Diagnostic settings |

> **SIEM mapping note**: In Sentinel, `NonInteractiveUserSignInLogs` maps to the `AADNonInteractiveUserSignInLogs` table. In Splunk, the same data arrives via the `azure:aad:signin` sourcetype. In Elastic, it lands in `azure.signinlogs`. The **field names within each record** (e.g., `ResultType`, `UserPrincipalName`, `IPAddress`) are consistent across all destinations because they originate from the same Entra ID diagnostic schema.

---

## 1. SKU gating — what you can and cannot detect

Identity Protection features are **licence-dependent**. Detection content must declare which tier it requires.

| Feature | Entra ID P1 | Entra ID P2 | Free |
|---|---|---|---|
| `SigninLogs` table | Yes | Yes | Yes (limited) |
| `RiskLevelDuringSignIn` column | No | Yes | No |
| `RiskState`, `RiskDetail` columns | No | Yes | No |
| `RiskEventTypes_V2` column | No | Yes | No |
| `risky Users` / `riskDetections` APIs | No | Yes | No |
| Conditional Access policy evaluation logs | Yes | Yes | No |
| `AADNonInteractiveUserSignInLogs` | Yes | Yes | No |
| `ManagedIdentitySignInLogs` | Yes | Yes | No |
| `ServicePrincipalSignInLogs` | Yes | Yes | No |

**Gotcha**: A detection that filters on `RiskLevelDuringSignIn == "high"` silently returns zero results in P1 tenants — the column exists but contains only `"none"`. In KQL, use `column_ifexists()` for P2-only columns. In SPL/other SIEMs, apply equivalent null-safe field access. Always declare the SKU tier requirement in detection content.

---

## 2. Sign-in risk vs user risk

Two distinct risk models that are often confused:

| Concept | Sign-in risk | User risk |
|---|---|---|
| Scope | Per-authentication event | Per-user entity (cumulative) |
| Column | `RiskLevelDuringSignIn` | `RiskLevelAggregated` (via `risky Users` API) |
| Triggers | Anomalous IP, impossible travel, AiTM proxy, malware-linked IP | Leaked credentials, confirmed compromise, cumulative sign-in risk |
| Remediation | MFA challenge, block | Password reset, block, confirm compromise |
| Detection use | Real-time alerting on suspicious sign-ins | Trend analysis, account compromise confirmation |

**Detection discipline**: Use sign-in risk for real-time detection rules. Use user risk for enrichment and escalation logic, not as a primary detection signal (it lags).

---

## 3. ResultType code catalogue (critical subset)

`ResultType` in `SigninLogs` is a **string**, not an integer. Always compare as string.

| Code | Meaning | Detection relevance |
|---|---|---|
| `"0"` | Success | Baseline; combine with anomalous context |
| `"50126"` | Invalid credentials | Password spray, brute force |
| `"50053"` | Account locked | Brute force threshold reached |
| `"50057"` | Account disabled | Attempted use of disabled account |
| `"50074"` | MFA required (strong auth) | MFA challenge triggered |
| `"50076"` | MFA challenge failed | MFA bypass attempt |
| `"500121"` | MFA denied (user rejected) | MFA fatigue attack |
| `"50140"` | Keep Me Signed In (KMSI) interrupt | Session management |
| `"50158"` | External security challenge | Conditional Access external control |
| `"53003"` | Blocked by Conditional Access | Policy enforcement |
| `"530032"` | Blocked by security defaults | Baseline protection |
| `"700016"` | Application not found in tenant | Misconfigured or malicious app |
| `"7000218"` | Request body must contain client_assertion | Service principal auth issue |
| `"90094"` | Admin consent required | OAuth consent flow |

**Always comment ResultType codes inline** — reviewers and analysts cannot memorise them.

---

## 4. Detection-relevant platform behaviours

The signals below describe **what Entra ID emits** when specific identity-layer activity occurs. They are not attack descriptions — pair with threat vector objects (TVMs) for adversary context.

### 4.1 Credential failure patterns

| Signal | Log category | Key fields |
|---|---|---|
| High failure rate per IP | `SigninLogs` | `IPAddress`, `ResultType` (`"50126"`, `"50053"`, `"50064"`), `UserPrincipalName` |
| Many distinct users per IP | `SigninLogs` | `UserPrincipalName` (distinct count), `IPAddress` |
| Account lockout triggered | `SigninLogs` | `ResultType == "50053"` |
| Disabled account access attempt | `SigninLogs` | `ResultType == "50057"` |

### 4.2 MFA challenge signals

| Signal | Log category | Key fields |
|---|---|---|
| MFA denial burst | `SigninLogs` | `ResultType == "500121"`, `UserPrincipalName` |
| MFA success after denials | `SigninLogs` | `ResultType == "0"` following `"500121"` for same user |
| MFA call limit reached | `SigninLogs` | `ResultType == "50088"` |
| Risky MFA enrolment blocked | `SigninLogs` | `ResultType == "53004"` |

### 4.3 Token and session anomalies

| Signal | Log category | Key fields |
|---|---|---|
| Sign-in with elevated risk | `SigninLogs` | `RiskLevelDuringSignIn` (P2 only) |
| Token replay indicator | `SigninLogs` | `CorrelationId`, `TokenIssuerType`, `IPAddress` mismatch |
| Non-interactive sign-in from new device | `NonInteractiveUserSignInLogs` | `DeviceDetail`, `IPAddress` |
| PRT usage indicator | `SigninLogs` | `AuthenticationProcessingDetails` contains `"Is Primary Refresh Token"` |

### 4.4 Consent and application changes

| Signal | Log category | Key fields |
|---|---|---|
| New consent grant | `AuditLogs` | `OperationName == "Consent to application"` |
| High-privilege permission granted | `AuditLogs` | `TargetResources[0].modifiedProperties` |
| New credential added to app/SP | `AuditLogs` | `OperationName in ("Add service principal credentials", "Update application – Certificates and secrets management")` |
| Federated credential added | `AuditLogs` | `OperationName has "federatedIdentityCredential"` |

### 4.5 Directory and policy changes

| Signal | Log category | Key fields |
|---|---|---|
| Conditional Access policy modified | `AuditLogs` | `OperationName has "conditional access"`, `TargetResources` |
| Permanent role assignment | `AuditLogs` | `OperationName == "Add member to role"` |
| PIM role activation | `AuditLogs` | `OperationName == "Add member to role completed (PIM activation)"` |
| Service principal sign-in from new IP | `ServicePrincipalSignInLogs` | `ServicePrincipalId`, `IPAddress` |

---

## 5. Telemetry split — user vs service principal vs managed identity

| Principal type | Sign-in log category | Audit log category |
|---|---|---|
| Interactive user | `SigninLogs` | `AuditLogs` |
| Non-interactive user | `NonInteractiveUserSignInLogs` | `AuditLogs` |
| Service principal | `ServicePrincipalSignInLogs` | `AuditLogs` |
| Managed identity | `ManagedIdentitySignInLogs` | `AuditLogs` |

**Common mistake**: Querying only interactive sign-ins and missing non-interactive activity. Token refresh, background app activity, and service-to-service calls appear in the non-interactive and service principal log categories.

For comprehensive identity coverage, query across all relevant sign-in categories. Example (KQL — adapt to your SIEM's query language):

```kql
// Sentinel / KQL example — adapt for Splunk, Elastic, etc.
union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d)
| where ResultType == "0"
// ... detection logic
```

---

## 6. Cross-tenant and B2B considerations

| Scenario | Column | Value |
|---|---|---|
| Home tenant sign-in | `HomeTenantId == ResourceTenantId` | Normal |
| Guest user (B2B) | `HomeTenantId != ResourceTenantId` | Cross-tenant access |
| External identity provider | `TokenIssuerType` | `"External"` |

**Detection discipline**: B2B guest access is legitimate but high-risk. Detections should distinguish between established B2B relationships and novel cross-tenant access.

---

## 7. Nested JSON field paths

Many sign-in and audit log fields contain nested JSON objects. The **field paths below are consistent across all SIEMs** — only the extraction syntax differs (KQL `parse_json()`, SPL `spath`, Elastic nested field access, etc.).

### SigninLogs nested fields

| Top-level field | Nested path | Type | Use |
|----------------|-------------|------|-----|
| `LocationDetails` | `.city` | string | Geo-anomaly detection |
| `LocationDetails` | `.countryOrRegion` | string | Impossible travel |
| `LocationDetails` | `.state` | string | Regional baselining |
| `DeviceDetail` | `.browser` | string | User agent anomaly |
| `DeviceDetail` | `.operatingSystem` | string | Platform baselining |
| `DeviceDetail` | `.isCompliant` | bool | Device compliance check |
| `DeviceDetail` | `.deviceId` | string | Device identity correlation |
| `ConditionalAccessPolicies` | `[].displayName` | string (array) | Which CA policies evaluated |
| `ConditionalAccessPolicies` | `[].result` | string (array) | `"success"`, `"failure"`, `"notApplied"` |
| `AuthenticationDetails` | `[].authenticationMethod` | string (array) | MFA method used |
| `AuthenticationDetails` | `[].succeeded` | bool (array) | Per-step auth result |
| `AuthenticationProcessingDetails` | `[].key` | string (array) | Contains `"Is Primary Refresh Token"` for PRT usage |

### AuditLogs nested fields

| Top-level field | Nested path | Type | Use |
|----------------|-------------|------|-----|
| `InitiatedBy` | `.user.userPrincipalName` | string | Who performed the action |
| `InitiatedBy` | `.app.displayName` | string | App-initiated changes |
| `TargetResources` | `[0].displayName` | string | Target object name |
| `TargetResources` | `[0].userPrincipalName` | string | Target user |
| `TargetResources` | `[0].modifiedProperties` | array | What changed (old/new values) |

---

## 8. Directory role and PIM monitoring

### Critical directory roles

| Role | Risk | Why |
|------|------|-----|
| Global Administrator | Critical | Full tenant control — can reset any password, modify any policy |
| Privileged Role Administrator | Critical | Can assign any role including Global Admin |
| Application Administrator | High | Can create/modify app registrations and consent to permissions |
| Cloud Application Administrator | High | Same as above minus on-prem app proxy |
| Exchange Administrator | High | Mailbox access, mail flow rules — BEC enabler |
| Security Administrator | High | Can modify security policies, read all security data |
| Conditional Access Administrator | High | Can weaken or disable CA policies |
| Partner Tier2 Support | Critical | Delegated admin — supply-chain attack vector |

### Key AuditLogs operations for role monitoring

| Operation | `OperationName` value | What it means |
|-----------|----------------------|---------------|
| PIM activation | `"Add member to role completed (PIM activation)"` | Just-in-time role elevation |
| Permanent assignment | `"Add member to role"` | Bypasses PIM — persistence risk |
| Role removal | `"Remove member from role"` | Privilege revocation or cleanup |
| Eligible assignment | `"Add eligible member to role in PIM"` | PIM-eligible (not yet active) |

For example queries, see [references/Detection-Cheatsheet.md](references/Detection-Cheatsheet.md).

---

## 9. Token and session mechanics

Understanding token types is critical for detecting token theft and replay:

| Token | Lifetime | Storage | Theft vector |
|-------|----------|---------|-------------|
| **Access token** | 60–90 min (configurable) | Memory | Process memory dump, AiTM proxy |
| **Refresh token** | 90 days (sliding) | Disk/browser | Malware, AiTM, device compromise |
| **Primary Refresh Token (PRT)** | 14 days | TPM-bound (ideally) | `mimikatz`, `ROADtools`, device compromise |
| **Session cookie** | Varies | Browser | Cookie theft, AiTM proxy |
| **FOCI token** | Varies | Shared across FOCI apps | One compromised FOCI app exposes others |

### FOCI (Family of Client IDs)

Microsoft first-party apps share refresh tokens via FOCI. If an attacker steals a refresh token for one FOCI app (e.g., Outlook), they can exchange it for tokens to other FOCI apps (e.g., Teams, OneDrive) without re-authenticating. Key FOCI client IDs:

| App | Client ID |
|-----|-----------|
| Microsoft Office | `d3590ed6-52b3-4102-aeff-aad2292ab01c` |
| Microsoft Teams | `1fec8e78-bce4-4aaf-ab1b-5451cc387264` |
| Outlook Mobile | `27922004-5251-4030-b22d-91ecd9a37ea4` |
| OneDrive | `ab9b8c07-8f02-4f72-87fa-80105867a763` |

### Token theft detection signals

| Signal | Log category | Key fields |
|--------|-------------|------------|
| Access token replay from new IP | `SigninLogs` | Same `CorrelationId`, different `IPAddress` |
| Refresh token from anomalous device | `NonInteractiveUserSignInLogs` | `DeviceDetail` mismatch |
| PRT usage (pass-the-PRT) | `SigninLogs` | `AuthenticationProcessingDetails` contains `"Is Primary Refresh Token"` |
| Impossible travel on token refresh | `NonInteractiveUserSignInLogs` | Geo-distance between consecutive sign-ins |

---

## 10. Application and consent landscape

### App registration vs service principal

| Concept | Scope | Created by |
|---------|-------|-----------|
| **App registration** | Global (multi-tenant) or single-tenant | Developer |
| **Service principal** | Per-tenant instance | Auto-created on consent or provisioning |
| **Enterprise application** | UI name for service principal | — |

### Dangerous permissions to monitor

| Permission | Type | Risk |
|-----------|------|------|
| `Mail.ReadWrite` | Application | Read/write all mailboxes — BEC |
| `Files.ReadWrite.All` | Application | Read/write all OneDrive/SharePoint — exfiltration |
| `Directory.ReadWrite.All` | Application | Full directory modification — persistence |
| `RoleManagement.ReadWrite.Directory` | Application | Assign any directory role — privilege escalation |
| `AppRoleAssignment.ReadWrite.All` | Application | Grant any app permission — self-escalation |
| `User.ReadWrite.All` | Application | Modify any user — password reset, MFA bypass |

### Key AuditLogs operations for consent monitoring

| Operation | `OperationName` value | What it means |
|-----------|----------------------|---------------|
| User/admin consent | `"Consent to application"` | Permission grant — check `TargetResources[0].modifiedProperties` for scope |
| App role assignment | `"Add app role assignment to service principal"` | Application permission granted |
| OAuth2 permission grant | `"Add OAuth2PermissionGrant"` | Delegated permission granted |

For example queries, see [references/Detection-Cheatsheet.md](references/Detection-Cheatsheet.md).

---

## 11. Entity identifier alignment

| Concept | Entra ID / Sentinel | Defender | CrowdStrike |
|---|---|---|---|
| User | `UserPrincipalName`, `UserId` (GUID) | `AccountUpn`, `AccountSid` | `UserName` |
| Device | `DeviceDetail.deviceId` | `DeviceId` | `aid` |
| IP | `IPAddress` | `RemoteIP` | `RemoteAddressIP4` |
| Application | `AppId`, `AppDisplayName` | — | — |
| Service principal | `ServicePrincipalId` | — | — |

Cross-platform correlation happens at the SIEM/SOAR layer. The `UserPrincipalName` is the most reliable cross-platform join key for identity.

---

## 12. Detection cheatsheet

For example KQL queries covering password spray, MFA fatigue, AiTM chains, OAuth consent, SP credential addition, cross-tenant anomalies, and PIM activations, see [references/Detection-Cheatsheet.md](references/Detection-Cheatsheet.md). The logic and field names are portable — adapt the syntax to your SIEM.

---

## 13. Quality checklist

- [ ] SKU tier requirement declared (P1 vs P2).
- [ ] `column_ifexists()` used for P2-only columns.
- [ ] `ResultType` compared as string, not integer.
- [ ] ResultType codes commented inline with meaning.
- [ ] All relevant sign-in tables queried (interactive + non-interactive + SP where applicable).
- [ ] Nested JSON parsed via `parse_json()` / `todynamic()`.
- [ ] Cross-tenant scenarios considered (B2B guest access).
- [ ] Risk columns used for enrichment, not as sole detection signal in P1 environments.
- [ ] Directory role changes monitored (permanent assignments, PIM activations).
- [ ] Token type and theft vector documented for token-based detections.
- [ ] Dangerous application permissions flagged in consent-based detections.
- [ ] FOCI token sharing considered for token theft scope assessment.
- [ ] MITRE technique mapping accurate (T1078, T1098, T1556, T1621, T1557 as applicable).
- [ ] Coordinate with the relevant platform skill for query mechanics (`microsoft-sentinel`, `splunk-spl-processing`, `crowdstrike-falcon`, etc.) and `detection-engineering` for lifecycle.
