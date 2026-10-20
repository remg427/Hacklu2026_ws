---
name: email-and-collaboration
description: M365 email and collaboration security telemetry for detection engineering — Exchange Online mail flow (transport rules, journaling, DLP), mailbox delegation and forwarding rules, OAuth app permissions on mailboxes, SharePoint/OneDrive external sharing, Teams guest access, Purview Unified Audit Log (UAL) event types, MailItemsAccessed semantics, and BEC/phishing detection patterns. Use when authoring detections targeting email-based attacks, business email compromise, data exfiltration via collaboration tools, or insider threat indicators.
---

# Email & Collaboration — detection-relevant internals

This skill encodes how M365 email and collaboration services work at the level needed to detect BEC, phishing, data exfiltration, and insider threats through these channels.

> **Scope**: This skill covers Microsoft 365 (Exchange Online, SharePoint, OneDrive, Teams). Google Workspace, Slack, and other collaboration platforms are not covered. SIEM table names vary by platform — consult the relevant platform skill for ingestion specifics.

---

## 1. Exchange Online mail flow

### Message lifecycle

```
Sender → Exchange Online Transport Pipeline
  → Transport rules (mail flow rules) evaluated
  → DLP policies evaluated
  → Connector routing (on-prem, partner, internet)
  → Recipient mailbox delivery
  → Post-delivery actions (ZAP, Safe Links rewrite)
```

### Detection-relevant mail flow concepts

| Concept | Detail | Detection signal |
|---|---|---|
| **Transport rules** | Admin-created rules that modify, redirect, or block mail | New transport rule creation = potential BEC infrastructure. `Set-TransportRule` in UAL. |
| **Journal rules** | Copy all mail to a journal mailbox | New journal rule = potential exfiltration. `New-JournalRule` in UAL. |
| **Connectors** | Route mail to/from external systems | New outbound connector = potential mail redirection. |
| **ZAP (Zero-hour Auto Purge)** | Retroactively removes malicious messages post-delivery | `ZAP` events in `EmailPostDeliveryEvents` (Defender). |
| **Safe Links** | URL rewriting for click-time protection | `UrlClickEvents` (Defender) shows user clicks on rewritten URLs. |

---

## 2. Mailbox delegation and forwarding

### Forwarding mechanisms (BEC critical)

| Mechanism | How it works | Detection | Persistence level |
|---|---|---|---|
| **Inbox rules** | User-created rule forwarding/redirecting mail | `New-InboxRule`, `Set-InboxRule` in UAL. `OfficeActivity` with `Operation` = `New-InboxRule`. | Per-mailbox, survives password change |
| **SMTP forwarding** | `ForwardingSmtpAddress` on mailbox | `Set-Mailbox` with `ForwardingSmtpAddress` parameter. | Admin-level, survives password change |
| **Transport rule forwarding** | Org-wide rule redirecting mail | `New-TransportRule` in UAL. | Org-wide, admin-only |
| **Power Automate flow** | Automated flow forwarding mail | Flow creation events in UAL. | Per-user, survives password change |
| **Delegate access** | Another user granted access to mailbox | `Add-MailboxPermission` in UAL. | Admin-level |

### BEC forwarding detection priority

1. **Inbox rules with external forwarding** — most common BEC persistence. Look for rules with `ForwardTo`, `RedirectTo`, or `DeleteMessage` actions targeting external addresses.
2. **SMTP forwarding to external domain** — silent, admin-level. Check `ForwardingSmtpAddress` on all mailboxes.
3. **Delegate access grants** — `FullAccess`, `SendAs`, `SendOnBehalf` to unexpected users.

---

## 3. OAuth app permissions on mailboxes

### Application permissions (daemon access, no user context)

| Permission | What it grants | Risk |
|---|---|---|
| `Mail.Read` (Application) | Read all mail in all mailboxes | Full email exfiltration |
| `Mail.ReadWrite` (Application) | Read/write all mail | Email manipulation + exfiltration |
| `Mail.Send` (Application) | Send mail as any user | BEC impersonation |
| `MailboxSettings.ReadWrite` (Application) | Modify mailbox settings | Create forwarding rules silently |

**Detection**: `AuditLogs` with `OperationName` = `Consent to application`. Check `TargetResources[0].modifiedProperties` for granted permissions. Application permissions (vs delegated) are higher risk — they don't require user context.

---

## 4. MailItemsAccessed

`MailItemsAccessed` is a critical audit event (requires M365 E5 or Audit Premium) that logs every time a mail item is read.

| Field | Detail | Detection use |
|---|---|---|
| `MailAccessType` | `Bind` (individual item) or `Sync` (folder sync) | `Sync` from unexpected client = bulk exfiltration |
| `ClientInfoString` | Application identifier | `Client=OWA` vs `Client=REST;Client=RESTSystem` — REST API access from non-standard apps |
| `OperationCount` | Number of items accessed | High count in short window = bulk access |
| `SessionId` | Session correlation | Correlate with sign-in events |

**Detection patterns**:
- `Sync` operations from non-standard clients (not Outlook, OWA, or mobile)
- High `OperationCount` from a single session
- `MailItemsAccessed` from an IP that doesn't match the user's sign-in IP
- Access to mailboxes the user doesn't normally access (delegate abuse)

---

## 5. SharePoint / OneDrive

### External sharing

| Sharing level | Risk | Detection signal |
|---|---|---|
| **Anyone link** | Highest — no authentication required | `SharingSet` with `TargetUserOrGroupType` = `Guest` and link type = `Anonymous` |
| **Specific people (external)** | Medium — requires authentication | `SharingInvitationCreated` with external email |
| **Organisation-wide** | Low (internal) | `SharingSet` with org-wide scope |

### Detection-relevant operations

| Operation | UAL event | Detection use |
|---|---|---|
| File downloaded | `FileDownloaded` | Bulk download = exfiltration |
| File shared externally | `SharingSet`, `SharingInvitationCreated` | Data leak |
| Sharing link created | `AnonymousLinkCreated` | Anyone-accessible link |
| Site permission changed | `SiteCollectionAdminAdded` | Privilege escalation |
| Sensitivity label removed | `SensitivityLabelRemoved` | DLP bypass |
| File synced | `FileSyncDownloadedFull` | Bulk sync to unmanaged device |

---

## 6. Microsoft Teams

### Detection-relevant Teams operations

| Operation | UAL event | Detection use |
|---|---|---|
| Guest added to team | `MemberAdded` with `MemberRoleType` = `Guest` | External access |
| External user messaged | `MessageSent` to external recipient | Data leak via chat |
| App installed in team | `AppInstalled` | Malicious app / OAuth abuse |
| Meeting recording accessed | `RecordingAccessed` | Sensitive content access |
| Channel created | `ChannelAdded` | Shadow IT / unauthorised collaboration |
| Connector added | `ConnectorAdded` | Webhook-based data exfiltration |

---

## 7. Unified Audit Log (UAL) — Purview

The UAL is the central audit log for all M365 services. Key considerations:

| Aspect | Detail |
|---|---|
| **Retention** | 180 days (E5/Audit Premium) or 90 days (standard) |
| **Latency** | 60-90 minutes typical; can be up to 24 hours for some workloads |
| **Search** | `Search-UnifiedAuditLog` PowerShell cmdlet or Purview compliance portal |
| **SIEM ingestion** | Via diagnostic settings, Office 365 Management Activity API, or platform-specific connectors. Consult your platform skill for table names. |

### Critical UAL record types

| RecordType | Service | Key operations |
|---|---|---|
| `ExchangeItem` | Exchange | Mail access, send, delete |
| `ExchangeAdmin` | Exchange | Mailbox config, transport rules |
| `SharePoint` | SharePoint/OneDrive | File operations, sharing |
| `AzureActiveDirectory` | Entra ID | Sign-in, directory changes |
| `MicrosoftTeams` | Teams | Messaging, meetings, apps |
| `PowerBI` | Power BI | Report access, sharing |
| `SecurityComplianceCenter` | Purview | DLP, retention, eDiscovery |

---

## 8. BEC detection patterns

### Pattern 1: Account compromise → inbox rule → financial fraud

```
1. Credential phishing (AiTM) → successful sign-in from anomalous location
2. Inbox rule created: forward/redirect to external address, or delete messages matching keywords
3. Attacker monitors email for financial transactions
4. Attacker sends fraudulent payment instructions from compromised account
```

**Detection chain**: Risky sign-in event → inbox rule creation (forward/redirect to external) → outbound email with financial keywords. Correlate across identity logs, UAL, and email delivery logs.

### Pattern 2: OAuth consent phishing → persistent access

```
1. Phishing email with OAuth consent link
2. User grants permissions to malicious app
3. App accesses mail/files via Graph API without further authentication
4. Access persists even after password change
```

**Detection**: Consent grant event with high-privilege permissions (`Mail.Read`, `Files.ReadWrite.All`). App not in organisation's approved list. See `entra-id` skill for consent monitoring.

### Pattern 3: Insider threat — bulk data exfiltration

```
1. User downloads large volumes of files from SharePoint/OneDrive
2. User shares files externally via anonymous links
3. User forwards email to personal account
```

**Detection**: Volume-based anomaly on `FileDownloaded` + `AnonymousLinkCreated` + `Set-Mailbox ForwardingSmtpAddress` per user per time window.

---

## 9. Telemetry sources

| M365 operation | UAL operation name | API source | Licence |
|---|---|---|---|
| Email delivery | `MailItemsAccessed`, `Send` | Office 365 Management Activity API | E3/E5 |
| Email URL clicks | `ClickData` | Defender for Office 365 API | Defender P1/P2 |
| Email attachments | (embedded in delivery events) | Defender for Office 365 API | Defender P1/P2 |
| Post-delivery actions (ZAP) | `ZAP` | Defender for Office 365 API | Defender P1/P2 |
| Inbox rule changes | `New-InboxRule`, `Set-InboxRule` | Office 365 Management Activity API | E3/E5 |
| Mailbox config changes | `Set-Mailbox` | Office 365 Management Activity API | E3/E5 |
| SharePoint file operations | `FileDownloaded`, `FileUploaded`, `AnonymousLinkCreated` | Office 365 Management Activity API | E3/E5 |
| Teams operations | `MemberAdded`, `ChatCreated` | Office 365 Management Activity API | E3/E5 |
| MailItemsAccessed | `MailItemsAccessed` | Office 365 Management Activity API | E5 / Audit Premium |

> Map these operations to your SIEM's tables/indexes. Consult the relevant platform skill (`microsoft-sentinel`, `splunk-spl-processing`, etc.) for ingestion specifics.

---

## 10. Quality checklist

- [ ] Forwarding detection covers all mechanisms (inbox rules, SMTP forwarding, transport rules, Power Automate).
- [ ] OAuth consent detections distinguish application vs delegated permissions.
- [ ] MailItemsAccessed detections check `MailAccessType` (Bind vs Sync) and `ClientInfoString`.
- [ ] SharePoint sharing detections distinguish anonymous links from authenticated sharing.
- [ ] BEC detection chains correlate sign-in anomaly → mailbox manipulation → financial indicators.
- [ ] UAL latency (60-90 min) accounted for in near-real-time detection design.
- [ ] Audit Premium / E5 requirements declared for MailItemsAccessed detections.
- [ ] Teams guest access and app installation monitored.
- [ ] Bulk download/sync thresholds documented with rationale.
- [ ] Transport rule and journal rule creation monitored as admin-level persistence.
