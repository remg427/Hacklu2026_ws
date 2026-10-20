# Entra ID Sign-In ResultType Codes — Security Detection Reference

`ResultType` in `SigninLogs` / `AADNonInteractiveUserSignInLogs` is a **string**. Always compare as string in KQL.

> Source: [Microsoft Entra ID error codes](https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes)

## Authentication failures

| Code | Name | Detection relevance |
|------|------|---------------------|
| `0` | Success | Baseline; combine with anomalous context (location, device, risk) |
| `50034` | UserAccountNotFound | Username enumeration — attacker probing for valid accounts |
| `50053` | IdsLocked | Account lockout — brute-force threshold reached |
| `50055` | InvalidPasswordExpiredPassword | Stale compromised credential reuse or dormant account abuse |
| `50056` | InvalidOrNullPassword | Credential stuffing against passwordless accounts |
| `50057` | UserDisabled | Disabled account sign-in — compromised credentials of terminated user |
| `50064` | CredentialAuthenticationError | Password spray or brute-force indicator |
| `50126` | InvalidUserNameOrPassword | High volume = password spray, credential stuffing, brute-force |
| `50105` | EntitlementGrantsNotFound | Privilege probing — user not assigned to app role |
| `50012` | AuthenticationFailed | Certificate/signing auth failure — possible token forgery |
| `50132` | SsoArtifactInvalidOrExpired | Post-compromise password reset race conditions |
| `50133` | SsoArtifactRevoked | Session revoked after password change — persistence loss |
| `50135` | PasswordChangeCompromisedPassword | Identity Protection flagged account as compromised |
| `50140` | KmsiInterrupt | "Keep me signed in" interrupt — session persistence baselining |
| `50173` | ExpiredOrRevokedGrant | Token replay after credential rotation |
| `50196` | LoopDetected | Abusive token requests — token theft tool or misconfigured malware |

## MFA-related

| Code | Name | Detection relevance |
|------|------|---------------------|
| `50072` | UserStrongAuthEnrollmentRequiredInterrupt | User without MFA — high-value target for AiTM |
| `50074` | UserStrongAuthClientAuthNRequiredInterrupt | Failed MFA — MFA fatigue, bypass attempt, AiTM proxy |
| `50076` | UserStrongAuthClientAuthNRequired | MFA required by CA — baseline for enforcement |
| `50078` | UserStrongAuthExpired | MFA session expired — stale session token replay |
| `50079` | UserStrongAuthEnrollmentRequired | Unenrolled user — MFA coverage gap |
| `50088` | TelecomMfaCallLimitReached | MFA call limit — MFA fatigue / push-bombing |
| `500121` | MFA denied | User rejected MFA push — MFA fatigue attack |
| `53004` | ProofUpBlockedDueToRisk | Risky MFA enrollment blocked — attacker registering their own MFA |
| `53010` | ProofUpBlockedDueToSecurityInfoAcr | MFA setup from untrusted location blocked |
| `53011` | UserBlockedDueToRisk | High-risk user blocked by Identity Protection |
| `50158` | ExternalSecurityChallenge | Third-party MFA redirect — monitor for bypass or downgrade |
| `90072` | PassThroughUserMfaError | Federated user MFA failure — federation trust abuse |

## Conditional Access

| Code | Name | Detection relevance |
|------|------|---------------------|
| `50005` | DevicePolicyError | Unsupported platform blocked — policy evasion from unusual OS |
| `50097` | DeviceAuthenticationRequired | Unmanaged device access attempt |
| `50131` | ConditionalAccessFailed | Broad CA block — correlate with risk signals |
| `50142` | PasswordChangeRequiredByCA | Risk-based forced password change |
| `53000` | DeviceNotCompliant | Non-compliant device — attacker using unmanaged endpoint |
| `53001` | DeviceNotDomainJoined | Non-domain-joined device blocked |
| `53002` | ApplicationUsedIsNotAnApprovedApp | Shadow IT or attacker tooling |
| `53003` | BlockedByConditionalAccess | Primary CA enforcement signal |
| `530032` | BlockedByConditionalAccessOnSecurityPolicy | Security policy enforcement |
| `530034` | DelegatedAdminBlockedDueToSuspiciousActivity | Supply-chain / partner compromise |
| `530035` | BlockedBySecurityDefaults | Legacy auth blocked — IMAP/SMTP spray |
| `70043` | BadTokenDueToSignInFrequency | Stale token replay against frequency-enforced apps |

## Token and grant

| Code | Name | Detection relevance |
|------|------|---------------------|
| `50027` | InvalidJwtToken | Token forgery or manipulation attempt |
| `50089` | FlowTokenExpired | Replayed or stolen auth artefacts |
| `50099` | PKeyAuthInvalidJwtUnauthorized | Device certificate spoofing |
| `54005` | AuthCodeAlreadyRedeemed | OAuth code replay attack |
| `70000` | InvalidGrant | Token theft and replay from different device |
| `70008` | ExpiredOrRevokedGrant | Stale credential reuse |
| `700082` | ExpiredOrRevokedGrantInactiveToken | Dormant account token replay |
| `900384` | JwtSignatureValidationFailed | Token forgery / Golden SAML |

## Account state and cross-tenant

| Code | Name | Detection relevance |
|------|------|---------------------|
| `50002` | NotAllowedTenant | Tenant restriction bypass attempt |
| `50020` | UserUnauthorized | B2B abuse or wrong IdP |
| `51004` | UserAccountNotInDirectory | Enumeration or misdirected federation auth |
| `500021` | TenantRestrictionDenied | Data exfiltration via alternate tenant |
| `500212` | NotAllowedByOutboundPolicy | Outbound cross-tenant exfil attempt |
| `500213` | NotAllowedByInboundPolicy | External attacker resource access attempt |
| `50129` | DeviceIsNotWorkplaceJoined | Unregistered device access |
| `50155` | DeviceAuthenticationFailed | Device certificate spoofing |
| `135011` | DeviceDisabled | Decommissioned device reuse |
| `80012` | OnPremLogonInvalidHours | After-hours access from compromised on-prem account |

## Application consent and authorisation

| Code | Name | Detection relevance |
|------|------|---------------------|
| `65001` | DelegationDoesNotExist | Illicit consent grant setup (OAuth phishing) |
| `65004` | UserDeclinedConsent | User awareness of suspicious consent prompt |
| `90094` | AdminConsentRequired | Privilege escalation via OAuth app |
| `700016` | UnauthorizedClient_DoesNotMatchRequest | Rogue application or misconfigured OAuth phishing |
| `7000112` | UnauthorizedClientApplicationDisabled | Compromised app reactivation attempt |
| `7000215` | InvalidClientSecret | Brute-force against service principal credentials |
| `7000222` | InvalidClientSecretExpiredKeysProvided | Stale SP credential reuse |
| `650056` | MisconfiguredApplication | Illicit consent grant in progress |
