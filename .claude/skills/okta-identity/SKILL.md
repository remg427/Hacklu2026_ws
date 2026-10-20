---
name: okta-identity
description: Okta identity platform detection guidance — System Log event schema (eventType taxonomy, actor/target/outcome structure), session token mechanics, authentication flows (FastPass, FIDO2, delegated auth), admin API abuse patterns, ThreatInsight signals, Okta-to-Entra federation trust chains, and Okta-specific attack patterns (cross-tenant impersonation, HAR file session theft, MFA factor reset abuse, inbound federation hijacking). Use for identity-focused detections targeting Okta telemetry ingested into SIEMs.
---

# Okta Identity — detection authoring

Okta is a major non-Microsoft identity platform with its own telemetry schema, attack surface, and detection patterns. This skill covers the platform internals needed to write detections against Okta System Log events, regardless of which SIEM ingests them.

> **Not to be confused with** `entra-id` (Microsoft Entra ID) or `identity-providers` (cross-vendor identity mechanics).

---

## 1. System Log event schema

Every Okta event follows a consistent JSON structure:

| Field | Type | Detection use |
|---|---|---|
| `eventType` | string | Primary event classifier. Hierarchical dot-notation (e.g. `user.session.start`). |
| `actor` | object | Who performed the action. Contains `id`, `type`, `alternateId` (email), `displayName`. |
| `target[]` | array | What was acted upon. Array of objects with `id`, `type`, `alternateId`, `displayName`. **Search by `type`, not array position** — target order is not guaranteed. |
| `outcome` | object | `result` (`SUCCESS`, `FAILURE`, `SKIPPED`, `UNKNOWN`) + `reason` string. |
| `client` | object | Client context: `userAgent`, `zone`, `device`, `ipAddress`, `geographicalContext`. |
| `authenticationContext` | object | `authenticationProvider`, `credentialType`, `externalSessionId`, `interface`. |
| `securityContext` | object | `isProxy` (boolean), `asNumber`, `asOrg`, `isp`, `domain`. IP reputation context. |
| `debugContext.debugData` | object | Unstable but valuable: `requestUri`, `dtHash`, `threatSuspected`, `logOnlySecurityData`, `behaviors`. |
| `transaction` | object | `id` (correlation key), `type` (`WEB` or `JOB`), `detail.requestApiTokenId` (API token used). |
| `published` | ISO 8601 | Event timestamp. |
| `severity` | enum | `DEBUG`, `INFO`, `WARN`, `ERROR`. |
| `uuid` | string | Unique event identifier. |

### Key eventType taxonomy

| Category | eventType pattern | Examples |
|---|---|---|
| **Authentication** | `user.session.*` | `user.session.start`, `user.session.end` |
| **MFA** | `user.authentication.auth_via_mfa` | MFA challenge result |
| **MFA factor lifecycle** | `system.mfa.factor.*` | `system.mfa.factor.activate`, `system.mfa.factor.deactivate`, `user.mfa.factor.reset_all` |
| **User lifecycle** | `user.lifecycle.*` | `user.lifecycle.create`, `user.lifecycle.activate`, `user.lifecycle.suspend`, `user.lifecycle.deactivate` |
| **Password** | `user.credential.*` | `user.credential.password.update`, `user.credential.forgot_password` |
| **App access** | `user.authentication.sso` | SSO into an application |
| **Admin actions** | `user.account.*` | `user.account.privilege.grant`, `user.account.update_profile` |
| **Policy changes** | `policy.lifecycle.*` | `policy.lifecycle.create`, `policy.lifecycle.update`, `policy.lifecycle.delete` |
| **IdP lifecycle** | `system.idp.lifecycle.*` | `system.idp.lifecycle.create`, `system.idp.lifecycle.update` |
| **API token** | `system.api_token.*` | `system.api_token.create`, `system.api_token.revoke` |
| **Group membership** | `group.user_membership.*` | `group.user_membership.add`, `group.user_membership.remove` |
| **Suspicious activity** | `user.account.report_suspicious_activity_by_enduser` | End-user reported suspicious activity |
| **Rate limiting** | `system.org.rate_limit.*` | Rate limit warnings and violations |

---

## 2. Authentication flows

### Standard sign-in flow

```
User → Okta sign-in page → Primary auth (password/IWA/delegated)
  → MFA challenge (push/TOTP/FIDO2/FastPass)
  → Session token issued → SSO to applications
```

### Delegated authentication

When Okta delegates to Active Directory, the `authenticationContext.authenticationProvider` is `ACTIVE_DIRECTORY` and `credentialType` is `IWA` or `LDAP_INTERFACE`. The password is validated by AD, not Okta — Okta cannot detect password spray against delegated auth directly.

### FastPass (Okta Verify device-bound)

FastPass is Okta's phishing-resistant authenticator. Key detection signal: `user.authentication.auth_via_mfa` with `outcome.reason eq "FastPass declined phishing attempt"` — this fires when FastPass detects an AiTM proxy.

### Device code flow

`eventType eq "user.authentication.auth_via_mfa"` with `authenticationContext.credentialType eq "DEVICE_CODE"`. Monitor for abuse — device code phishing is a growing attack vector.

---

## 3. Attack patterns

### 3.1 Cross-tenant impersonation (Scattered Spider pattern)

The most significant Okta-specific attack pattern. Flow:
1. Social engineer IT help desk to reset MFA for a Super Administrator
2. Enrol attacker-controlled MFA factors
3. Create a second Identity Provider (inbound federation)
4. Manipulate username parameter in source IdP to impersonate target users
5. SSO into applications as any user

**Detection signals:**

| Stage | System Log query | Notes |
|---|---|---|
| MFA factor reset | `eventType eq "user.mfa.factor.reset_all"` | Alert on any all-factor reset for admin accounts |
| New IdP created | `eventType eq "system.idp.lifecycle.create"` | Critical — should be extremely rare |
| IdP modified | `eventType sw "system.idp.lifecycle"` | Broader — catches create + update + delete |
| Auth via external IdP | `eventType eq "user.authentication.auth_via_IDP"` | Alert if org doesn't use inbound federation |
| Admin privilege grant | `eventType eq "user.account.privilege.grant"` | Privilege escalation |

### 3.2 Session token theft (HAR file exfiltration)

Okta session tokens stolen from HAR files (browser network recordings shared with support). The `externalSessionId` in `authenticationContext` is the session correlation key.

**Detection**: Alert on session reuse from a different IP/ASN than the original authentication:
- Correlate `externalSessionId` across events
- Flag when `client.ipAddress` or `securityContext.asNumber` changes mid-session

### 3.3 MFA fatigue / push bombing

Repeated MFA push notifications to exhaust the user into approving.

**Detection**: `eventType eq "user.authentication.auth_via_mfa"` with `outcome.result eq "FAILURE"` — count failures per user per time window. Threshold: >5 failures in 10 minutes.

### 3.4 Admin API token abuse

API tokens provide persistent access without MFA. Stolen tokens enable silent admin operations.

**Detection signals:**
- `eventType eq "system.api_token.create"` — new token creation
- `transaction.detail.requestApiTokenId` present in events — identifies API-driven actions
- Correlate API token usage with `client.ipAddress` — flag novel IPs

### 3.5 Policy weakening

Attacker modifies authentication policies to remove MFA requirements or weaken session controls.

**Detection**: `eventType sw "policy.lifecycle"` — alert on any policy modification, especially:
- `policy.rule.update` where MFA requirements are removed
- `policy.lifecycle.delete` for authentication policies

---

## 4. ThreatInsight and behavioural signals

Okta ThreatInsight provides pre-built threat detection signals available in the System Log.

| Signal | `eventType` / field | Detection use |
|---|---|---|
| **Credential stuffing** | `security.threat.detected` with `debugContext.debugData.threatSuspected` | Automated credential attacks against the org |
| **Password spray** | `security.threat.detected` | Distributed password guessing |
| **Suspicious IP** | `securityContext.isProxy` = `true` | Traffic from anonymising proxies, VPNs, Tor |
| **Brute force lockout** | `user.account.lock` | Account locked due to repeated failures |
| **Anomalous location** | `debugContext.debugData.behaviors` containing `New Geo-Location` | Sign-in from unusual geography |
| **Anomalous device** | `debugContext.debugData.behaviors` containing `New Device` | Sign-in from unrecognised device |
| **Suspicious activity report** | `user.account.report_suspicious_activity_by_enduser` | End-user self-reported compromise |

> `debugContext.debugData.behaviors` is a JSON string containing Okta's behavioural analysis. Parse it to extract individual signals. Note: `debugContext` fields are unstable and may change between releases.

---

## 5. Okta Workflows and automation abuse

| Attack vector | `eventType` | Detection signal |
|---|---|---|
| **Workflow creation** | `system.workflow.create` | New automation — check for data exfiltration flows |
| **Workflow modification** | `system.workflow.update` | Changed automation — may add malicious steps |
| **Workflow with external connector** | `system.workflow.create` / `update` | Connector to external service (Slack, email, HTTP) — data exfiltration channel |
| **Workflow execution** | `system.workflow.execute` | Automated action triggered — correlate with workflow definition |

**Risk**: Okta Workflows can automate user provisioning, group membership changes, and external API calls. An attacker with admin access can create workflows that silently exfiltrate data or maintain persistence.

---

## 6. OAuth app and integration abuse

| Attack vector | `eventType` | Detection signal |
|---|---|---|
| **App integration created** | `app.lifecycle.create` | New app integration — potential OAuth consent phishing |
| **App assigned to user/group** | `app.user_membership.add` / `group.application.assignment.add` | App access granted — check if app is legitimate |
| **OAuth scope grant** | `app.oauth2.consent.grant` | OAuth consent granted — check scope breadth |
| **App credentials rotated** | `app.credential.update` | App secret changed — potential credential theft |
| **SAML certificate change** | `app.credential.update` (SAML app) | Signing certificate changed — potential Golden SAML setup |

**Risk**: Attackers can create rogue app integrations to harvest OAuth tokens, or modify existing SAML app certificates to forge assertions.

---

## 7. SIEM ingestion patterns

> Column/field names vary by SIEM and connector version. Consult your SIEM's Okta integration documentation for exact field mappings.

| Okta native field | Telemetry type | Ingestion method | Notes |
|---|---|---|---|
| System Log events | Identity audit log | SIEM connector (API polling or Event Hook) | Primary detection source |
| `eventType` | Event classifier | Mapped to SIEM-specific field | Use as primary filter |
| `actor.alternateId` | User identity | Mapped to SIEM user field | Email address |
| `outcome.result` | Action result | Mapped to SIEM result field | SUCCESS / FAILURE |
| `client.ipAddress` | Source IP | Mapped to SIEM source IP field | Client IP |
| `published` | Event timestamp | Mapped to SIEM timestamp field | ISO 8601 |
| `securityContext` | IP reputation | Mapped to SIEM enrichment fields | Proxy, ASN, ISP |

### Ingestion methods

| Method | Latency | Notes |
|---|---|---|
| **API polling** (System Log API) | Minutes | Most common; SIEM polls `/api/v1/logs` on interval |
| **Event Hooks** (webhook push) | Near-real-time | Okta pushes events to SIEM endpoint; requires SIEM webhook receiver |
| **Log streaming** (AWS EventBridge) | Near-real-time | Native integration for AWS-based SIEMs |

---

## 8. Cross-platform entity correlation

When correlating Okta events with other identity or endpoint platforms, align on these entity categories:

| Entity type | Okta field | Correlation key |
|---|---|---|
| **User** | `actor.alternateId` (email) | Email / UPN — matches across most IdPs when email is consistent |
| **User ID** | `actor.id` (Okta UUID) | Platform-specific — requires mapping table for cross-platform joins |
| **Session** | `authenticationContext.externalSessionId` | Okta-specific — correlate within Okta events only |
| **IP address** | `client.ipAddress` | Universal — correlate across all platforms |
| **Application** | `target[].alternateId` (app label) | App name — may differ across platforms; use app ID where available |
| **Device** | `client.device` / `debugContext.debugData.dtHash` | Device hash — Okta-specific; correlate with endpoint platforms via device ID mapping |

> Cross-platform correlation works best on `actor.alternateId` (email) ↔ UPN when the email address is consistent across identity platforms. For user ID correlation, maintain a mapping table between Okta UUIDs and other platform identifiers.

---

## 9. Quality checklist

- [ ] `eventType` used as primary filter (not `displayMessage` which is human-readable and unstable).
- [ ] `outcome.result` checked for SUCCESS/FAILURE as appropriate.
- [ ] `target[]` searched by `type`, not array index (target order is not guaranteed).
- [ ] `securityContext.isProxy` considered for anonymising proxy detection.
- [ ] `authenticationContext.externalSessionId` used for session correlation.
- [ ] `debugContext.debugData` fields treated as unstable (may change between releases).
- [ ] SIEM field mappings validated against connector documentation (field names vary by SIEM and connector version).
- [ ] Admin account detections scoped to Super Administrator / Org Administrator roles.
- [ ] Inbound federation events (`system.idp.lifecycle.*`) monitored — especially if feature is not in use.
- [ ] API token creation (`system.api_token.create`) and usage (`transaction.detail.requestApiTokenId`) monitored.
- [ ] ThreatInsight signals (`security.threat.detected`) ingested and correlated.
- [ ] Okta Workflows creation and modification monitored for data exfiltration risk.
- [ ] OAuth app integration creation and scope grants monitored.
- [ ] MFA factor reset for admin accounts always generates high-severity alerts.
- [ ] Session hijacking detection: IP/ASN change mid-session on `externalSessionId`.
- [ ] Delegated authentication limitations documented (Okta cannot detect password spray against AD-delegated auth).
