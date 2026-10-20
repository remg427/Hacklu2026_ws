---
name: identity-providers
description: Cross-vendor identity mechanics for detection engineering — OAuth2/OIDC token flows (authorization code, client credentials, device code, ROPC), SAML assertion structure and forgery conditions (Golden SAML), Primary Refresh Token (PRT) mechanics, refresh token binding and lifetime, federation trust chains (ADFS-to-Entra, Okta-to-Entra), MFA ceremony flows (push, FIDO2, TOTP, phone), conditional access evaluation order, and session token lifecycle. Use when authoring detections that need to understand authentication protocol mechanics regardless of the specific identity platform.
---

# Identity Providers — cross-vendor authentication mechanics

This skill encodes how modern authentication protocols actually work at the level needed to detect abuse. It is vendor-neutral — specific platform telemetry lives in `entra-id`, `okta-identity`, and `active-directory`.

---

## 1. OAuth 2.0 / OIDC token flows

### Authorization code flow (most common for web apps)

```
User → App → Redirect to IdP /authorize
  → User authenticates + consents
  → IdP redirects back with authorization code
  → App exchanges code for tokens (POST /token)
  → IdP returns: access_token + id_token + refresh_token
```

**Detection-relevant**: The code-to-token exchange happens server-side. A replayed authorization code (`AADSTS54005` in Entra ID) indicates code interception.

### Client credentials flow (service-to-service)

```
Service → POST /token with client_id + client_secret (or certificate)
  → IdP returns: access_token (no refresh token, no user context)
```

**Detection-relevant**: No user interaction. Compromised client secrets enable persistent access. Monitor for: new credential additions to app registrations, token requests from unexpected IPs, expired secret usage.

### Device code flow

```
Device → POST /devicecode → receives user_code + device_code
  → User visits verification URL, enters user_code, authenticates
  → Device polls /token with device_code until user completes auth
  → IdP returns tokens
```

**Detection-relevant**: Device code phishing — attacker sends the user_code to the victim, who authenticates on the attacker's behalf. The attacker's device receives the tokens. Detection: `device_code` grant type from unexpected device/IP, or user authenticating device codes they didn't initiate.

### Resource Owner Password Credentials (ROPC)

```
App → POST /token with username + password directly
  → IdP returns tokens
```

**Detection-relevant**: ROPC bypasses MFA and conditional access in many configurations. Its use in modern environments is almost always suspicious. Detection: `grant_type=password` in token requests.

---

## 2. SAML assertion structure

```xml
<saml:Assertion>
  <saml:Issuer>https://adfs.contoso.com/</saml:Issuer>
  <ds:Signature>...</ds:Signature>
  <saml:Subject>
    <saml:NameID>user@contoso.com</saml:NameID>
  </saml:Subject>
  <saml:Conditions NotBefore="..." NotOnOrAfter="...">
    <saml:AudienceRestriction>
      <saml:Audience>urn:federation:MicrosoftOnline</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AttributeStatement>
    <saml:Attribute Name="http://schemas.microsoft.com/identity/claims/objectidentifier">
      <saml:AttributeValue>user-guid</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>
```

### Golden SAML attack

**Preconditions**: Attacker has the ADFS token-signing certificate private key.

**Mechanism**: Forge SAML assertions for any user, any role, any audience — the relying party (e.g. Entra ID) trusts the signature.

**Detection signals**:
- SAML assertion without corresponding ADFS authentication event
- Token-signing certificate exported (EID 1007 on ADFS server)
- Assertion `NotBefore`/`NotOnOrAfter` window anomalies
- Assertion claims that don't match the user's actual attributes in AD
- `TokenIssuerType` = `External` in Entra ID `SigninLogs` when it should be `AzureAD`

---

## 3. Primary Refresh Token (PRT)

The PRT is a long-lived token issued to Windows devices joined to Entra ID. It enables SSO across all Entra ID-integrated applications.

| Concept | Detail | Detection relevance |
|---|---|---|
| **Issuance** | Issued during Windows logon to Entra ID-joined/hybrid-joined devices | PRT is bound to the device's TPM-protected key |
| **Usage** | Transparently presented to Entra ID during browser SSO | `x-ms-RefreshTokenCredential` header in authentication requests |
| **Theft** | Extracting PRT from device memory (e.g. `BrowserCore.exe`, `CloudAP` plugin) | Stolen PRT used from a different device — detectable via device ID mismatch |
| **Pass-the-PRT** | Using stolen PRT to authenticate as the user from attacker's device | `DeviceDetail.deviceId` in `SigninLogs` doesn't match the user's registered device |

**Detection**: Correlate `DeviceDetail.deviceId` in sign-in events with the user's registered devices. PRT usage from an unregistered device is high-signal.

---

## 4. Refresh token mechanics

| Property | Detail | Detection relevance |
|---|---|---|
| **Lifetime** | Typically 90 days (Entra ID), configurable per IdP | Expired token reuse = `AADSTS70008` |
| **Binding** | Can be bound to device, IP, or session | Token used from different device/IP = potential theft |
| **Rotation** | New refresh token issued on each use (sliding window) | Old refresh token reuse after rotation = replay attack |
| **Revocation** | Password change, admin revocation, session policy | Revoked token use = `AADSTS50173` |
| **Family** | Refresh tokens form a family; revoking one revokes all | Limits blast radius of token theft |

### Token theft detection patterns

1. **IP change**: Refresh token used from a different IP than the original authentication
2. **Device change**: Token used from a different device fingerprint
3. **Concurrent use**: Same refresh token used from two locations simultaneously
4. **Post-revocation use**: Token used after password change or admin revocation

---

## 5. Federation trust chains

### ADFS → Entra ID

```
User → ADFS (on-prem) → authenticates via AD
  → ADFS issues SAML assertion
  → Entra ID validates assertion signature against trusted certificate
  → Entra ID issues OAuth tokens
```

**Detection**: `TokenIssuerType` in `SigninLogs`. `AzureAD` = cloud-native auth. `External` = federated. Monitor for unexpected federation sources.

### Okta → Entra ID (inbound federation)

```
User → Okta (source IdP) → authenticates
  → Okta issues SAML assertion
  → Entra ID (target) validates and issues tokens
```

**Detection**: `system.idp.lifecycle.create` in Okta System Log. `user.authentication.auth_via_IDP` for auth via external IdP. In Entra ID: `TokenIssuerType` = `External`.

### Trust chain abuse patterns

| Attack | Mechanism | Detection |
|---|---|---|
| **Golden SAML** | Forge assertions with stolen signing key | Assertion without IdP auth event |
| **Federation hijacking** | Add attacker-controlled IdP as trusted source | IdP creation/modification events |
| **Shadow federation** | Create secondary federation relationship | New federation trust in directory audit logs |
| **Token signing cert rotation** | Replace legitimate cert with attacker-controlled | Certificate change events on ADFS/IdP |

---

## 6. MFA ceremony flows

### Push notification (Okta Verify, Microsoft Authenticator)

```
User authenticates with password → IdP sends push to registered device
  → User approves/denies on device → IdP validates response
```

**Vulnerability**: MFA fatigue — repeated pushes until user approves. **Detection**: Multiple push denials followed by approval. Okta: `outcome.result eq "FAILURE"` on `user.authentication.auth_via_mfa` followed by `SUCCESS`. Entra ID: `ResultType 500121` (denied) followed by `0` (success).

### FIDO2 / WebAuthn

```
User authenticates → IdP sends challenge → Authenticator signs challenge
  with device-bound private key → IdP validates signature
```

**Phishing-resistant**: The authenticator validates the origin (domain) — AiTM proxies cannot relay the challenge because the origin doesn't match. **Detection**: `FastPass declined phishing attempt` in Okta. FIDO2 authentication events in Entra ID.

### TOTP (Time-based One-Time Password)

```
User authenticates → enters 6-digit code from authenticator app
  → IdP validates code against shared secret + current time
```

**Vulnerability**: Phishable — AiTM proxy can capture and replay the TOTP in real-time. **Detection**: TOTP authentication from known AiTM infrastructure (IP reputation), or TOTP followed by immediate session from different IP.

---

## 7. Policy-based access evaluation

Modern IdPs enforce access decisions through policy engines that evaluate context at sign-in time. The concept is the same across vendors — only the implementation differs:

| IdP | Policy engine | Evaluation factors |
|-----|--------------|--------------------|
| Entra ID | Conditional Access | User/group, app, device state, location, risk level, grant controls (MFA, compliance) |
| Okta | Authentication Policies + Global Session Policy | User/group, app, device trust, network zone, behaviour |
| Google Workspace | Context-Aware Access | User/group, device, IP range, geo, device security posture |

**Detection-relevant**: Policy bypass attempts and policy weakening are high-signal across all IdPs. Monitor for:
- Access attempts blocked by policy (indicates probing or misconfiguration)
- Policy modifications that remove MFA requirements or exclude privileged roles
- Changes to trusted network/location definitions

For Entra ID-specific Conditional Access evaluation order, `ResultType` codes, and `AuditLogs` operations, see the `entra-id` skill.

---

## 8. Quality checklist

- [ ] Detection targets the protocol-level behaviour, not a specific IdP's UI.
- [ ] OAuth grant type identified (auth code, client credentials, device code, ROPC).
- [ ] Token lifetime and binding assumptions documented.
- [ ] Federation trust chain understood (which IdP issues, which validates).
- [ ] MFA ceremony type considered (phishing-resistant vs phishable).
- [ ] Token theft detection covers IP change, device change, and concurrent use.
- [ ] SAML assertion forgery conditions understood (signing key compromise).
- [ ] PRT theft detection correlates device ID with registered devices.
- [ ] Policy-based access bypass attempts monitored (Conditional Access, Okta policies, etc.).
- [ ] Cross-IdP correlation uses email/UPN as the join key.
