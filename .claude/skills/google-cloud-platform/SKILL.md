---
name: google-cloud-platform
description: Google Cloud Platform security telemetry for detection engineering — Cloud Audit Logs structure (Admin Activity, Data Access, System Event, Policy Denied), IAM mechanics (roles, service accounts, workload identity federation, impersonation), GCP-specific attack patterns (service account key theft, cross-project access, storage exfiltration), VPC Flow Logs, and the mapping to Google SecOps (Chronicle) YARA-L and SIEM ingestion. Use when authoring detections targeting GCP infrastructure abuse.
---

# Google Cloud Platform — detection-relevant internals

This skill covers GCP cloud infrastructure security telemetry and the internals needed to detect abuse.

---

## 1. Cloud Audit Logs

GCP generates four types of audit logs:

| Log type | What it captures | Default | Detection use |
|---|---|---|---|
| **Admin Activity** | Resource configuration changes (create, delete, modify) | Always on, cannot be disabled | Primary detection source — control plane operations |
| **Data Access** | Resource data read/write (e.g. reading a GCS object) | Off by default (must enable) | Data exfiltration detection — critical gap if not enabled |
| **System Event** | GCP-initiated system actions | Always on | Infrastructure changes by Google (maintenance, auto-scaling) |
| **Policy Denied** | Access denied by VPC Service Controls or org policies | Always on | Privilege probing, policy bypass attempts |

### Audit log structure

| Field | Description | Detection use |
|---|---|---|
| `protoPayload.methodName` | API method called (e.g. `google.iam.admin.v1.CreateServiceAccount`) | Primary event classifier |
| `protoPayload.authenticationInfo.principalEmail` | Caller identity | Who performed the action |
| `protoPayload.requestMetadata.callerIp` | Source IP | Geolocation, anomaly detection |
| `protoPayload.authorizationInfo[]` | Permissions checked and granted/denied | Privilege analysis |
| `protoPayload.serviceData` / `protoPayload.request` | Request details | Operation-specific context |
| `resource.type` | GCP resource type (e.g. `gcs_bucket`, `gce_instance`) | Resource targeting |
| `resource.labels.project_id` | Project context | Cross-project access detection |
| `severity` | `INFO`, `WARNING`, `ERROR` | Error = potential access denied |

---

## 2. IAM mechanics

### Identity types

| Type | Identifier | Credentials | Detection relevance |
|---|---|---|---|
| **Google Account** | `user:email@gmail.com` | OAuth, password + MFA | Human user access |
| **Service Account** | `serviceAccount:name@project.iam.gserviceaccount.com` | Keys (JSON/P12) or workload identity | Long-lived keys are high-risk |
| **Google Group** | `group:name@domain.com` | Membership-based | Group membership changes = privilege changes |
| **Domain** | `domain:domain.com` | All users in domain | Overly broad grants |
| **allUsers** | `allUsers` | No authentication | Public access — always high-signal |
| **allAuthenticatedUsers** | `allAuthenticatedUsers` | Any Google account | Semi-public — still high-risk |

### Service account key lifecycle

| Operation | `methodName` | Detection signal |
|---|---|---|
| Key creation | `google.iam.admin.v1.CreateServiceAccountKey` | New long-lived credential — should be rare |
| Key deletion | `google.iam.admin.v1.DeleteServiceAccountKey` | Cleanup or anti-forensics |
| Key usage from external IP | Data Access logs | SA key used from outside GCP = potential theft |

**Critical**: Service account keys are the GCP equivalent of AWS access keys. They don't expire by default and provide persistent access. Key creation should be monitored and minimised — prefer workload identity federation.

### Workload identity federation

Allows external identities (AWS roles, Azure managed identities, OIDC providers) to impersonate GCP service accounts without keys.

**Detection**: `google.iam.credentials.v1.GenerateAccessToken` with `callerIp` from external cloud provider. Monitor for unexpected federation sources.

### Service account impersonation

```
User → iam.serviceAccounts.getAccessToken → SA token → API calls as SA
```

**Detection**: `google.iam.credentials.v1.GenerateAccessToken` — who is impersonating which service account, from where.

---

## 3. Critical detection events

### Persistence

| methodName | What it means |
|---|---|
| `google.iam.admin.v1.CreateServiceAccount` | New service account — backdoor identity |
| `google.iam.admin.v1.CreateServiceAccountKey` | New key for SA — credential persistence |
| `SetIamPolicy` (on any resource) | IAM policy change — privilege escalation |
| `google.cloud.functions.v1.CreateFunction` | New Cloud Function — code execution persistence |
| `google.compute.instances.v1.SetMetadata` | Instance metadata change — startup script persistence |

### Defence impairment

| methodName | What it means |
|---|---|
| `google.logging.v2.DeleteSink` | Log sink deleted — audit trail disruption |
| `google.logging.v2.UpdateSink` (with exclusion) | Log exclusion added — selective blindness |
| `SetIamPolicy` removing security roles | Security team access removed |
| `google.cloud.securitycenter.v1.UpdateFinding` (mute) | Security Command Center finding muted |

### Data exfiltration

| methodName | What it means |
|---|---|
| `storage.objects.get` | GCS object download (requires Data Access logging) |
| `storage.buckets.setIamPolicy` (allUsers) | Bucket made public |
| `compute.snapshots.create` + `compute.snapshots.setIamPolicy` | Disk snapshot shared externally |
| `bigquery.jobs.create` (export) | BigQuery data export |
| `storage.buckets.create` (in external project) | Data copied to attacker-controlled project |

---

## 4. GCP-specific attack patterns

> **Detection examples, not commands.** Each pattern is attacker behaviour a rule should catch. This skill does not perform the steps, does not request the metadata service, and does not read a credential from the machine that installed it.

### Pattern 1: Service account key theft → persistent access

1. Attacker compromises a workload with SA key access
2. Downloads SA key JSON file
3. Uses key from external infrastructure
4. **Detection**: SA key usage from non-GCP IP addresses

### Pattern 2: Metadata server abuse (SSRF → credential theft)

1. SSRF vulnerability in application running on GCE
2. Attacker queries the instance metadata service for the default service-account token. Match this in logs as an indicator: hostname `metadata.google.internal`, path ending in `service-accounts/default/token`. That pair is a string to detect, not a URL to fetch.
3. Obtains the service-account access token from that response
4. **Detection**: Token usage from unexpected IP (not the instance's IP)

### Pattern 3: Cross-project privilege escalation

1. Attacker has access to Project A
2. Service account in Project A has roles in Project B
3. Attacker impersonates SA to access Project B resources
4. **Detection**: Cross-project `SetIamPolicy` or resource access. `resource.labels.project_id` != caller's project.

---

## 5. IAM privilege escalation paths

GCP IAM misconfigurations enable privilege escalation through multiple vectors.

### IAM policy manipulation

| Escalation method | Required permission | `methodName` |
|---|---|---|
| Grant self Owner on project | `resourcemanager.projects.setIamPolicy` | `SetIamPolicy` |
| Grant self roles on service account | `iam.serviceAccounts.setIamPolicy` | `SetIamPolicy` |
| Create SA key for privileged SA | `iam.serviceAccountKeys.create` | `google.iam.admin.v1.CreateServiceAccountKey` |
| Impersonate privileged SA | `iam.serviceAccounts.getAccessToken` | `google.iam.credentials.v1.GenerateAccessToken` |
| Modify org policy to remove constraints | `orgpolicy.policy.set` | `google.orgpolicy.v2.OrgPolicy.CreatePolicy` |

### Compute-based escalation

| Escalation method | Mechanism | `methodName` |
|---|---|---|
| Set startup script on instance | Modify instance metadata | `compute.instances.setMetadata` |
| SSH via OS Login with sudo | OS Login role grants root | `google.cloud.oslogin.v1.OsLoginService.ImportSshPublicKey` |
| Create instance with privileged SA | Attach SA with broad roles | `compute.instances.create` |
| Cloud Function with privileged SA | Deploy function using SA | `google.cloud.functions.v1.CreateFunction` |
| Cloud Build with privileged SA | Submit build with SA | `google.devtools.cloudbuild.v1.CreateBuild` |

### Cross-project escalation

| Escalation method | Mechanism | Detection signal |
|---|---|---|
| SA in Project A has roles in Project B | Impersonate SA to access Project B | `resource.labels.project_id` != caller's project |
| Shared VPC abuse | Access resources in host project via service project | Cross-project network access |
| Cross-project `SetIamPolicy` | Grant self access in another project | `SetIamPolicy` with target in different project |

---

## 6. Organisation and folder-level attacks

| Attack vector | `methodName` | Detection signal |
|---|---|---|
| **Org policy modification** | `google.orgpolicy.v2.OrgPolicy.CreatePolicy` | Constraint removed or weakened |
| **Folder/project creation** | `google.cloud.resourcemanager.v3.Projects.CreateProject` | New project — potential shadow project |
| **Org IAM policy change** | `SetIamPolicy` at org level | Org-wide privilege grant |
| **Audit log sink deletion** | `google.logging.v2.DeleteSink` | Audit trail disruption |
| **Log exclusion creation** | `google.logging.v2.UpdateSink` with exclusion filter | Selective log blindness |
| **VPC Service Controls bypass** | `google.identity.accesscontextmanager.v1.UpdateServicePerimeter` | Perimeter weakened |

---

## 7. Container and serverless attacks

### GKE (Google Kubernetes Engine)

| Attack vector | Detection signal |
|---|---|
| Privileged pod deployment | Kubernetes audit logs — pod spec with `privileged: true` |
| GKE admin credential access | `google.container.v1.GetServerConfig` / cluster credential access |
| Workload identity abuse | SA token from GKE pod used for unexpected API calls |
| Container image poisoning | `google.devtools.artifactregistry.v1.CreateDockerImage` |
| Node pool with broad SA | `google.container.v1.CreateNodePool` with default SA |

### Cloud Functions / Cloud Run

| Attack vector | Detection signal |
|---|---|
| Function deployment with privileged SA | `google.cloud.functions.v1.CreateFunction` + SA with broad roles |
| Cloud Run service with SA accessing secrets | `google.cloud.run.v2.CreateService` + subsequent Secret Manager access |
| Pub/Sub trigger for persistence | `google.pubsub.v1.CreateSubscription` linked to function |
| Cloud Scheduler for persistence | `google.cloud.scheduler.v1.CreateJob` triggering function |

---

## 8. Network and infrastructure attacks

### VPC and network telemetry

| Source | What it captures | Detection use |
|---|---|---|
| **VPC Flow Logs** | Network flow metadata (src/dst IP, port, protocol, bytes) | Lateral movement, C2 beaconing, exfiltration volume |
| **Cloud DNS logs** | DNS queries from VPC | DNS tunnelling, DGA detection |
| **Cloud Armor logs** | WAF decisions | Web application attacks |
| **Firewall Rules Logging** | Firewall rule hits (allow/deny) | Network access patterns |

### Network-level attack events

| `methodName` | Detection signal |
|---|---|
| `compute.firewalls.insert` / `patch` (0.0.0.0/0 source) | Firewall opened to the internet |
| `compute.networks.addPeering` | New VPC peering — lateral movement path |
| `compute.routes.insert` | Route modification — traffic redirection |
| `compute.forwardingRules.insert` | New forwarding rule — potential traffic interception |
| `dns.changes.create` | DNS record modification — potential hijacking |

---

## 9. SIEM ingestion patterns

> Table/index names are SIEM-specific. Consult your SIEM's GCP integration documentation for exact configurations.

| GCP source | Telemetry type | Ingestion method | Notes |
|---|---|---|---|
| Admin Activity logs | Control-plane audit log | Pub/Sub → SIEM, or native Chronicle ingestion | Always on — primary detection source |
| Data Access logs | Data-plane audit log | Pub/Sub → SIEM, or native Chronicle ingestion | Must be explicitly enabled |
| System Event logs | GCP-initiated system actions | Pub/Sub → SIEM | Always on |
| Policy Denied logs | Access denied by VPC SC / org policies | Pub/Sub → SIEM | Always on |
| VPC Flow Logs | Network flow metadata | Pub/Sub → SIEM | Must be enabled per subnet |
| Security Command Center | Threat findings | Pub/Sub → SIEM, or SCC API | Pre-built threat detections |
| Cloud DNS logs | DNS queries | Pub/Sub → SIEM | Must be enabled |
| GKE audit logs | Kubernetes API server audit | Pub/Sub → SIEM | Must be enabled |

### Chronicle / Google SecOps

GCP audit logs are natively ingested into Chronicle and normalised to UDM (Unified Data Model). Detection rules use YARA-L 2.0. Key UDM fields:

| UDM field | Maps to |
|---|---|
| `metadata.event_type` | `USER_LOGIN`, `RESOURCE_CREATION`, etc. |
| `principal.user.email_addresses` | Caller identity |
| `principal.ip` | Source IP |
| `target.resource.name` | Target resource |
| `security_result.action` | `ALLOW`, `BLOCK` |

---

## 10. Quality checklist

- [ ] Data Access logging requirement declared (not enabled by default).
- [ ] `protoPayload.methodName` used as primary event filter.
- [ ] `principalEmail` distinguished between user (`user:`) and service account (`serviceAccount:`).
- [ ] Service account key creation monitored and minimised — prefer workload identity federation.
- [ ] Cross-project access patterns documented — `resource.labels.project_id` != caller's project.
- [ ] `allUsers` / `allAuthenticatedUsers` grants flagged as public access.
- [ ] Metadata server (169.254.169.254) abuse considered for SSRF scenarios.
- [ ] Log sink integrity monitored (deletion, exclusion addition).
- [ ] Workload identity federation sources validated — unexpected external IdPs flagged.
- [ ] SIEM ingestion method documented (Pub/Sub, Chronicle native, etc.).
- [ ] IAM privilege escalation paths monitored: `SetIamPolicy`, SA key creation, SA impersonation.
- [ ] Organisation-level operations monitored: org policy changes, folder/project creation.
- [ ] VPC Service Controls perimeter changes monitored.
- [ ] GKE admin credential access and privileged pod deployment monitored.
- [ ] Firewall rules allowing 0.0.0.0/0 source flagged.
- [ ] Cloud Function/Cloud Run deployment with privileged SA monitored.
