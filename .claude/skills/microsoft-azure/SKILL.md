---
name: microsoft-azure
description: Azure cloud infrastructure security telemetry for detection engineering — Azure Activity Log and Resource Manager operations, Azure RBAC model (roles, scopes, PIM), managed identity mechanics, Key Vault access patterns, storage account security, virtual machine and compute operations, network security groups, Azure Policy and Defender for Cloud signals. Use when authoring detections targeting Azure resource abuse, privilege escalation, data exfiltration, or persistence at the infrastructure layer. For Entra ID identity detections, use `entra-id` instead.
---

# Microsoft Azure — detection-relevant internals

This skill covers Azure cloud infrastructure security. For Entra ID (identity/authentication), see `entra-id`. For Sentinel query mechanics, see `microsoft-sentinel`.

---

## 1. Azure Activity Log

Every Azure Resource Manager (ARM) operation generates an Activity Log entry. Key fields:

| Field | Type | Detection use |
|---|---|---|
| `operationName` | string | ARM operation (e.g. `Microsoft.Compute/virtualMachines/write`) |
| `caller` | string | UPN (user) or GUID (service principal) |
| `callerIpAddress` | string | Source IP |
| `status` | string | `Started`, `Succeeded`, `Failed` |
| `category` | string | `Administrative`, `Security`, `ServiceHealth`, `Policy` |
| `resourceId` | string | Full ARM resource path |
| `level` | string | `Informational`, `Warning`, `Error`, `Critical` |
| `claims` | object | JWT claims including `appid` (application ID), `oid` (object ID), `tid` (tenant ID) |

> Column names in your SIEM may differ from the Activity Log JSON field names. Consult your SIEM's Azure connector documentation for exact column mappings.

### Operation name patterns

ARM operations follow the pattern: `Microsoft.<Provider>/<resourceType>/<action>`

| Pattern | Examples | Detection use |
|---|---|---|
| `*/write` | `Microsoft.Compute/virtualMachines/write` | Resource creation/modification |
| `*/delete` | `Microsoft.Storage/storageAccounts/delete` | Resource destruction |
| `*/action` | `Microsoft.KeyVault/vaults/secrets/getSecret/action` | Privileged operations |
| `*/listKeys/action` | `Microsoft.Storage/storageAccounts/listKeys/action` | Credential access |

---

## 2. Azure RBAC

### Role hierarchy

| Scope | Example | Inheritance |
|---|---|---|
| **Management group** | `/providers/Microsoft.Management/managementGroups/mg1` | Inherits down to all subscriptions |
| **Subscription** | `/subscriptions/{sub-id}` | Inherits down to all resource groups |
| **Resource group** | `/subscriptions/{sub-id}/resourceGroups/{rg}` | Inherits down to all resources |
| **Resource** | `/subscriptions/{sub-id}/resourceGroups/{rg}/providers/...` | Specific resource only |

### Critical built-in roles

| Role | Scope | Risk | Detection signal |
|---|---|---|---|
| **Owner** | Any | Full control including RBAC | Role assignment at subscription/MG scope |
| **Contributor** | Any | Full control except RBAC | Resource creation/modification |
| **User Access Administrator** | Any | Can grant any role to anyone | Role assignment creation |
| **Key Vault Administrator** | Key Vault | Full secret/key/cert access | Secret access from unexpected principal |
| **Storage Blob Data Owner** | Storage | Full blob access bypassing ACLs | Data plane access |
| **Virtual Machine Contributor** | Compute | VM management including extensions | VM extension installation (code execution) |

### Privileged Identity Management (PIM)

PIM provides just-in-time role activation. Detection-relevant:
- `PIM` operations in `AuditLogs`: `Add member to role in PIM completed (permanent)` vs `(timebound)`
- Permanent role assignments bypass PIM controls — always alert
- Role activation from unexpected location/device

---

## 3. Managed identities

| Type | How it works | Detection relevance |
|---|---|---|
| **System-assigned** | Tied to a specific resource lifecycle | Token requests from the resource's IMDS endpoint |
| **User-assigned** | Independent lifecycle, can be shared | Can be attached to multiple resources — broader blast radius |

### Token acquisition

Managed identities acquire tokens via the Instance Metadata Service (IMDS) at `169.254.169.254`. The token is scoped to the identity's RBAC permissions.

**Detection**: Managed identity tokens used from outside Azure (IMDS is only accessible from within the VM). `CallerIpAddress` in Activity Log should be an Azure IP for managed identity operations.

---

## 4. Key Vault

| Operation | Detection signal |
|---|---|
| `SecretGet` | Secret accessed — correlate with caller identity and IP |
| `SecretSet` | Secret created/modified — potential credential storage |
| `SecretList` | Secret enumeration — reconnaissance |
| `KeySign` / `KeyDecrypt` | Cryptographic operations — potential data access |
| `CertificateGet` | Certificate accessed — potential for certificate-based auth abuse |
| `VaultAccessPolicyChange` | Access policy modified — privilege escalation |

Key Vault data-plane operations require diagnostic settings to be enabled. Logs are exported via diagnostic settings to your SIEM (Event Hub, storage account, or Log Analytics). Without diagnostic settings, Key Vault data-plane activity is invisible.

---

## 5. Storage account security

| Attack vector | Mechanism | Detection |
|---|---|---|
| **Public blob access** | Container access level set to `Blob` or `Container` | `Microsoft.Storage/storageAccounts/blobServices/containers/write` with public access |
| **SAS token abuse** | Shared Access Signature with excessive permissions/lifetime | SAS token usage from unexpected IP (storage analytics logs) |
| **Storage key access** | `listKeys` operation exposes full account access | `Microsoft.Storage/storageAccounts/listKeys/action` from non-admin |
| **Cross-tenant replication** | Object replication to external account | Replication policy creation to external destination |

---

## 6. Compute operations

### VM-level attacks

| Operation | Detection signal |
|---|---|
| `Microsoft.Compute/virtualMachines/extensions/write` | VM extension installation — arbitrary code execution on the VM |
| `Microsoft.Compute/virtualMachines/runCommand/action` | Run Command — remote code execution via ARM API |
| `Microsoft.Compute/virtualMachines/write` (with custom data) | Custom script execution during VM creation |
| `Microsoft.Compute/disks/beginGetAccess/action` | Disk export — data exfiltration via disk snapshot |
| `Microsoft.Compute/snapshots/write` + `Microsoft.Compute/snapshots/beginGetAccess/action` | Snapshot creation + export |

### Serverless (Functions, Logic Apps)

| Operation | Detection signal |
|---|---|
| Function deployment with external dependencies | Supply chain risk |
| Logic App connector creation to external services | Data exfiltration channel |
| Function with managed identity accessing Key Vault | Privilege chain |

---

## 7. Network security

| Resource | Detection-relevant operations |
|---|---|
| **NSG** | Rule additions allowing inbound from `0.0.0.0/0` (any) on sensitive ports |
| **Azure Firewall** | Policy modifications reducing protection |
| **Private endpoints** | Removal of private endpoints exposing services publicly |
| **DNS zones** | Record modifications (potential for DNS hijacking) |
| **VNet peering** | New peering to unexpected VNets (lateral movement path) |

---

## 8. Defender for Cloud signals

| Signal | Description | Detection use |
|---|---|---|
| Security alerts | Defender-generated threat detections | Active threat indicators |
| Recommendations | Misconfiguration and posture findings | Proactive risk identification |
| Secure Score changes | Security posture metric changes | Posture degradation tracking |
| Regulatory compliance | Compliance framework evaluation results | Compliance drift detection |

> Defender for Cloud findings are exported to your SIEM via the built-in connector or Event Hub. Consult your SIEM's Azure integration documentation for exact table names.

---

## 9. Privilege escalation paths

Azure RBAC misconfigurations and API permission abuse enable privilege escalation.

### Role assignment abuse

| Escalation method | Required role/permission | ARM operation | Detection signal |
|---|---|---|---|
| Assign Owner to self at subscription scope | User Access Administrator | `Microsoft.Authorization/roleAssignments/write` | Role assignment at subscription/MG scope |
| Assign Contributor to self | User Access Administrator | `Microsoft.Authorization/roleAssignments/write` | New role assignment from non-admin |
| Create custom role with wildcard actions | Owner | `Microsoft.Authorization/roleDefinitions/write` | Custom role with `*` actions |
| Elevate to Global Admin via subscription | Owner at root MG | `Microsoft.Authorization/elevateAccess/action` | Elevation API call — always high-signal |

### Compute-based escalation

| Escalation method | Mechanism | ARM operation |
|---|---|---|
| VM extension — arbitrary code execution | Install custom script extension on VM | `Microsoft.Compute/virtualMachines/extensions/write` |
| Run Command — remote code execution | Execute commands via ARM API | `Microsoft.Compute/virtualMachines/runCommand/action` |
| Custom script during VM creation | User data / custom script extension | `Microsoft.Compute/virtualMachines/write` |
| Automation Account runbook | Create/modify runbook with managed identity | `Microsoft.Automation/automationAccounts/runbooks/write` |
| Logic App with managed identity | Create Logic App that calls ARM APIs | `Microsoft.Logic/workflows/write` |
| Function App with managed identity | Deploy function that uses MI to access resources | `Microsoft.Web/sites/write` |

### Data-plane escalation

| Escalation method | Mechanism | Detection signal |
|---|---|---|
| Storage account key extraction | `listKeys` exposes full account access | `Microsoft.Storage/storageAccounts/listKeys/action` |
| Key Vault secret access | Access secrets via data plane | `SecretGet` in Key Vault diagnostic logs |
| Managed identity token theft | IMDS token used from outside Azure | `CallerIpAddress` is non-Azure IP for MI operations |
| SAS token generation with excessive scope | Generate SAS with broad permissions | Storage analytics logs — SAS usage from unexpected IP |

---

## 10. Subscription and management group attacks

| Attack vector | ARM operation | Detection signal |
|---|---|---|
| **Subscription takeover** | Transfer subscription to attacker tenant | `Microsoft.Subscription/cancel`, transfer operations |
| **Management group manipulation** | Move subscription between MGs | `Microsoft.Management/managementGroups/write` |
| **Policy exemption** | Exempt resources from Azure Policy | `Microsoft.Authorization/policyExemptions/write` |
| **Resource lock removal** | Remove delete locks | `Microsoft.Authorization/locks/delete` |
| **Diagnostic settings removal** | Disable logging | `Microsoft.Insights/diagnosticSettings/delete` |
| **Blueprint assignment change** | Modify governance blueprints | `Microsoft.Blueprint/blueprintAssignments/write` |

---

## 11. Container and serverless attacks

### AKS (Azure Kubernetes Service)

| Attack vector | Detection signal |
|---|---|
| Privileged pod deployment | Kubernetes audit logs — pod spec with `privileged: true` |
| AKS admin credential access | `Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action` |
| Cluster role binding escalation | Kubernetes RBAC changes in audit logs |
| Container registry image poisoning | `Microsoft.ContainerRegistry/registries/push/write` |
| AKS managed identity abuse | MI token used for ARM operations from cluster |

### Azure Functions / Logic Apps

| Attack vector | Detection signal |
|---|---|
| Function deployment with MI accessing Key Vault | `Microsoft.Web/sites/write` + subsequent `SecretGet` |
| Logic App connector to external service | `Microsoft.Logic/workflows/write` with external connector |
| Function with VPC integration accessing internal resources | Network-level detection via NSG flow logs |
| Timer-triggered function for persistence | `Microsoft.Web/sites/write` with timer trigger |

---

## 12. SIEM ingestion patterns

> Table/index names are SIEM-specific. Consult your SIEM's Azure integration documentation for exact table names and connector configurations.

| Azure source | Telemetry type | Ingestion method | Notes |
|---|---|---|---|
| Activity Log | ARM control-plane operations | Built-in SIEM connector / Event Hub | Always available — primary detection source |
| Entra ID Audit + Sign-in Logs | Identity-plane operations | Built-in SIEM connector / Event Hub | See `entra-id` skill |
| Key Vault diagnostic logs | Data-plane secret/key/cert operations | Diagnostic settings → Event Hub / storage | Must be explicitly enabled |
| Storage diagnostic logs | Blob/file/queue/table operations | Diagnostic settings → Event Hub / storage | Must be explicitly enabled |
| NSG flow logs | Network flow metadata | Storage account → SIEM connector | Requires NSG flow log configuration |
| Defender for Cloud alerts | Threat detections | Built-in SIEM connector / Event Hub | Requires Defender for Cloud |
| Azure Policy events | Compliance and policy evaluation | Activity Log (Policy category) | Always available |
| AKS audit logs | Kubernetes API server audit | Diagnostic settings → Event Hub / storage | Must be explicitly enabled |

---

## 13. Quality checklist

- [ ] `OperationNameValue` used as primary filter (not `OperationName` which is display-friendly).
- [ ] `ActivityStatusValue` checked for `Succeeded` (not just any status).
- [ ] `Caller` distinguished between UPN (user) and GUID (service principal).
- [ ] RBAC scope considered — subscription/MG-level role assignment is higher signal than resource-level.
- [ ] PIM activation vs permanent assignment distinguished.
- [ ] Managed identity token usage validated against expected source (Azure IP range).
- [ ] Key Vault diagnostic logging requirement declared.
- [ ] Storage account data plane logging requirement declared.
- [ ] VM extension and Run Command operations monitored.
- [ ] Cross-tenant/cross-subscription operations flagged.
- [ ] Privilege escalation paths monitored: role assignment creation, custom role creation, `elevateAccess` API.
- [ ] Compute-based escalation monitored: VM extensions, Run Command, Automation runbooks.
- [ ] Subscription-level governance changes monitored: policy exemptions, lock removal, diagnostic settings deletion.
- [ ] AKS admin credential access and privileged pod deployment monitored.
- [ ] Storage `listKeys` operations from non-admin principals flagged.
- [ ] `entra-id` skill referenced for identity-plane detections (not duplicated here).
