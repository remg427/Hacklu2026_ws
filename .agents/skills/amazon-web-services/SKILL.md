---
name: amazon-web-services
description: AWS security telemetry and internals for detection engineering — CloudTrail event structure (management vs data events, read-only vs write), IAM mechanics (roles, policies, assume-role chains, SCPs, permission boundaries), GuardDuty finding types, S3 access logging, VPC Flow Logs, Lambda execution model, cross-account access patterns, and the mapping between AWS operations and detection telemetry. Use when authoring detections targeting AWS cloud infrastructure abuse, privilege escalation, data exfiltration, or persistence.
---

# Amazon Web Services — detection-relevant internals

This skill encodes how AWS security-relevant services work at the level needed to detect cloud infrastructure abuse.

---

## 1. CloudTrail event structure

Every AWS API call generates a CloudTrail event. Key fields:

| Field | Type | Detection use |
|---|---|---|
| `eventSource` | string | AWS service (e.g. `iam.amazonaws.com`, `s3.amazonaws.com`) |
| `eventName` | string | API action (e.g. `CreateUser`, `PutBucketPolicy`) |
| `eventType` | string | `AwsApiCall`, `AwsConsoleSignIn`, `AwsServiceEvent` |
| `sourceIPAddress` | string | Caller IP. `AWS Internal` for service-initiated. |
| `userIdentity` | object | Who made the call. Contains `type`, `arn`, `accountId`, `principalId`. |
| `userIdentity.type` | string | `Root`, `IAMUser`, `AssumedRole`, `FederatedUser`, `AWSService` |
| `requestParameters` | object | API call parameters (varies per API) |
| `responseElements` | object | API response (varies per API) |
| `errorCode` | string | `AccessDenied`, `UnauthorizedAccess`, etc. |
| `readOnly` | boolean | `true` = read operation, `false` = write/mutate |
| `managementEvent` | boolean | `true` = control plane, `false` = data plane |

### Management vs data events

| Type | Examples | Default logging |
|---|---|---|
| **Management events** | `CreateUser`, `RunInstances`, `PutBucketPolicy` | Logged by default |
| **Data events** | `GetObject` (S3), `Invoke` (Lambda) | NOT logged by default — must enable |

**Critical gap**: S3 object-level access (`GetObject`, `PutObject`) is NOT in CloudTrail by default. Without data event logging, S3 exfiltration is invisible.

---

## 2. IAM mechanics

### Identity types

| Type | `userIdentity.type` | Credentials | Detection relevance |
|---|---|---|---|
| **Root** | `Root` | Email + password + MFA | Root usage is always high-signal |
| **IAM user** | `IAMUser` | Access key + secret key, or console password | Long-lived credentials. Key rotation discipline. |
| **Assumed role** | `AssumedRole` | Temporary credentials from `sts:AssumeRole` | Cross-account access, privilege escalation |
| **Federated user** | `FederatedUser` | SAML/OIDC federation | External IdP trust chain |
| **AWS service** | `AWSService` | Service-linked role | `sourceIPAddress` = `AWS Internal` |

### Assume-role chains

```
IAM User (Account A) → AssumeRole → Role (Account B) → AssumeRole → Role (Account C)
```

Each hop creates a new set of temporary credentials. The `userIdentity.arn` shows the assumed role, but `userIdentity.sessionContext.sessionIssuer` reveals the original identity.

**Detection**: Unusual assume-role chains (depth > 2), cross-account role assumptions from unexpected accounts, role assumption from unexpected source IPs.

### Policy evaluation order

```
1. SCPs (Service Control Policies) — org-level deny
2. Resource-based policies — allow/deny on the resource
3. IAM permission boundaries — maximum permissions
4. Identity-based policies — user/role permissions
5. Session policies — temporary credential restrictions
```

**Detection-relevant**: An `AccessDenied` error may indicate SCP enforcement (legitimate) or privilege probing (suspicious). Correlate with the caller's expected permissions.

---

## 3. Critical detection events

### Persistence

| eventName | Service | What it means |
|---|---|---|
| `CreateUser` | IAM | New IAM user — backdoor account |
| `CreateAccessKey` | IAM | New access key for existing user — credential persistence |
| `CreateLoginProfile` | IAM | Console password added to IAM user |
| `AttachUserPolicy` / `AttachRolePolicy` | IAM | Policy attachment — privilege escalation |
| `PutUserPolicy` / `PutRolePolicy` | IAM | Inline policy — harder to audit than managed policies |
| `CreateRole` | IAM | New role — potential for assume-role abuse |
| `UpdateAssumeRolePolicy` | IAM | Trust policy modification — who can assume the role |

### Defence impairment

| eventName | Service | What it means |
|---|---|---|
| `StopLogging` / `DeleteTrail` | CloudTrail | Audit trail disabled |
| `PutEventSelectors` | CloudTrail | Logging scope reduced |
| `DeleteFlowLogs` | VPC | Network visibility removed |
| `DisableGuardDuty` / `DeleteDetector` | GuardDuty | Threat detection disabled |
| `PutBucketLogging` (disable) | S3 | Access logging disabled |

### Data exfiltration

| eventName | Service | What it means |
|---|---|---|
| `GetObject` | S3 | Object download (requires data event logging) |
| `PutBucketPolicy` (public) | S3 | Bucket made public |
| `CreateSnapshot` + `ModifySnapshotAttribute` | EC2 | EBS snapshot shared with external account |
| `CopySnapshot` | EC2 | Snapshot copied to attacker account |
| `CreateDBSnapshot` + `ModifyDBSnapshotAttribute` | RDS | Database snapshot shared externally |

---

## 4. GuardDuty finding types

GuardDuty findings follow the pattern: `ThreatPurpose:ResourceType/ThreatName`.

| Category | Example findings | Detection use |
|---|---|---|
| **Credential access** | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | Instance role credentials used from outside AWS |
| **Persistence** | `Persistence:IAMUser/AnomalousBehavior` | Unusual API calls for the identity |
| **Privilege escalation** | `PrivilegeEscalation:IAMUser/AdministrativePermissions` | Policy granting admin access |
| **Exfiltration** | `Exfiltration:S3/MaliciousIPCaller` | S3 access from known-bad IP |
| **Crypto mining** | `CryptoCurrency:EC2/BitcoinTool.B!DNS` | DNS queries to mining pools |
| **Stealth** | `Stealth:IAMUser/CloudTrailLoggingDisabled` | CloudTrail disabled |

---

## 5. Cross-account access patterns

| Pattern | Mechanism | Detection signal |
|---|---|---|
| **Cross-account role assumption** | `sts:AssumeRole` with external account ID | `userIdentity.accountId` != resource account |
| **Resource-based policy sharing** | S3 bucket policy, KMS key policy granting external access | `Principal` in policy contains external account |
| **Organisation access** | SCPs, delegated admin, StackSets | `userIdentity.type` = `AWSService` with org context |
| **External ID requirement** | `sts:AssumeRole` with `ExternalId` condition | Missing ExternalId = confused deputy vulnerability |

---

## 6. IAM privilege escalation paths

AWS IAM misconfigurations enable privilege escalation through multiple vectors. Each path has a corresponding CloudTrail `eventName` for detection.

### Policy manipulation

| Escalation method | Required permissions | CloudTrail `eventName` |
|---|---|---|
| Create new policy version with admin access | `iam:CreatePolicyVersion` | `CreatePolicyVersion` |
| Set default to a more permissive existing version | `iam:SetDefaultPolicyVersion` | `SetDefaultPolicyVersion` |
| Attach admin policy to user/group/role | `iam:AttachUserPolicy` / `AttachGroupPolicy` / `AttachRolePolicy` | `AttachUserPolicy`, `AttachGroupPolicy`, `AttachRolePolicy` |
| Create inline policy with admin access | `iam:PutUserPolicy` / `PutGroupPolicy` / `PutRolePolicy` | `PutUserPolicy`, `PutGroupPolicy`, `PutRolePolicy` |
| Add self to a more privileged group | `iam:AddUserToGroup` | `AddUserToGroup` |

### Credential theft / creation

| Escalation method | Required permissions | CloudTrail `eventName` |
|---|---|---|
| Create access key for another user | `iam:CreateAccessKey` | `CreateAccessKey` |
| Create console login for another user | `iam:CreateLoginProfile` | `CreateLoginProfile` |
| Reset another user's console password | `iam:UpdateLoginProfile` | `UpdateLoginProfile` |
| Modify role trust policy to allow self to assume | `iam:UpdateAssumeRolePolicy` | `UpdateAssumeRolePolicy` |

### Service-based escalation (PassRole abuse)

| Escalation method | Required permissions | CloudTrail `eventName` |
|---|---|---|
| Launch EC2 with privileged instance profile | `iam:PassRole` + `ec2:RunInstances` | `RunInstances` |
| Create Lambda with privileged role, invoke it | `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | `CreateFunction20150331`, `Invoke20150331` |
| Update existing Lambda code to abuse its role | `lambda:UpdateFunctionCode` | `UpdateFunctionCode20150331v2` |
| Create CloudFormation stack with privileged role | `iam:PassRole` + `cloudformation:CreateStack` | `CreateStack` |
| Create Glue dev endpoint with privileged role | `iam:PassRole` + `glue:CreateDevEndpoint` | `CreateDevEndpoint` |
| Create Data Pipeline with privileged role | `iam:PassRole` + `datapipeline:CreatePipeline` | `CreatePipeline` |
| Create SageMaker notebook with privileged role | `iam:PassRole` + `sagemaker:CreateNotebookInstance` | `CreateNotebookInstance` |

**Detection principle**: Monitor `iam:PassRole` usage — any API call that accepts a `RoleArn` parameter is a potential escalation vector. Correlate with the role's attached policies to assess blast radius.

---

## 7. AWS Organizations and multi-account attacks

### Organisation-level operations

| eventName | Detection signal |
|---|---|
| `CreateAccount` / `InviteAccountToOrganization` | New account added — potential shadow account |
| `LeaveOrganization` | Account leaving org — loses SCP protection |
| `CreatePolicy` / `UpdatePolicy` / `DeletePolicy` (SCP) | SCP modification — org-wide security boundary change |
| `AttachPolicy` / `DetachPolicy` (SCP) | SCP attachment change — may remove guardrails from accounts |
| `EnableAWSServiceAccess` | New service granted org-wide access |
| `RegisterDelegatedAdministrator` | Account granted delegated admin — elevated cross-account access |

### Cross-account attack patterns

| Pattern | Mechanism | Detection |
|---|---|---|
| **Confused deputy** | Service assumes role without ExternalId validation | `AssumeRole` without `ExternalId` in `requestParameters` |
| **Role chain abuse** | Multi-hop assume-role to reach target account | Assume-role depth > 2; `sessionContext.sessionIssuer` chain analysis |
| **Resource policy backdoor** | S3/KMS/SQS policy grants access to external account | `PutBucketPolicy`, `PutKeyPolicy` with external `Principal` |
| **StackSets abuse** | CloudFormation StackSets deploy resources across accounts | `CreateStackSet` / `CreateStackInstances` targeting multiple accounts |

---

## 8. Serverless and container attacks

### Lambda

| eventName | Detection signal |
|---|---|
| `CreateFunction20150331` | New function — check role, runtime, code source |
| `UpdateFunctionCode20150331v2` | Code update — potential code injection |
| `UpdateFunctionConfiguration20150331v2` | Config change — environment variables may contain secrets |
| `AddPermission20150331` | Resource policy change — who can invoke the function |
| `CreateEventSourceMapping` | New trigger — may enable data exfiltration pipeline |

**Lambda-specific risks**: Environment variables may contain secrets in plaintext. Lambda layers can inject malicious code. Functions with VPC access can reach internal resources.

### ECS / EKS

| Attack vector | Detection signal |
|---|---|
| Privileged container deployment | `RunTask` / `CreateService` with privileged task definition |
| Container escape to host | Host-level CloudTrail events from container IP |
| EKS RBAC abuse | Kubernetes audit logs (separate from CloudTrail) |
| Task role credential theft | Task role credentials used from outside the container (similar to EC2 IMDS abuse) |
| ECR image poisoning | `PutImage` to shared ECR repository |

---

## 9. Network and infrastructure attacks

### VPC and network telemetry

| Source | What it captures | Detection use |
|---|---|---|
| **VPC Flow Logs** | Network flow metadata (src/dst IP, port, protocol, action) | Lateral movement, C2 beaconing, data exfiltration volume |
| **Route 53 query logs** | DNS queries from VPC | DNS tunnelling, DGA detection |
| **ELB access logs** | HTTP/S request metadata | Web application attacks, unusual access patterns |
| **WAF logs** | Web application firewall decisions | Attack attempts, rule bypass |

### Network-level attack events

| eventName | Detection signal |
|---|---|
| `AuthorizeSecurityGroupIngress` (0.0.0.0/0) | Security group opened to the internet |
| `CreateVpcPeeringConnection` | New VPC peering — lateral movement path |
| `ModifyVpcEndpoint` | VPC endpoint change — may bypass network controls |
| `AssociateRouteTable` / `CreateRoute` | Route table modification — traffic redirection |
| `DeleteFlowLogs` | Network visibility removed |

---

## 10. SIEM ingestion patterns

> Table/index names below are illustrative. Consult your SIEM's AWS integration documentation for exact table names, sourcetypes, or index configurations.

| AWS source | Telemetry type | Ingestion method | Notes |
|---|---|---|---|
| CloudTrail | Control-plane audit log | S3 → SIEM connector, or EventBridge | Primary detection source |
| CloudTrail (data events) | Data-plane audit log | S3 → SIEM connector (separate trail) | Must be explicitly enabled |
| GuardDuty | Threat findings | EventBridge → SIEM, or S3 export | Pre-built threat detections |
| VPC Flow Logs | Network flow metadata | CloudWatch Logs → SIEM, or S3 | Network telemetry |
| S3 access logs | Object-level access | S3 → SIEM | Requires server access logging enabled |
| Route 53 query logs | DNS queries | CloudWatch Logs → SIEM | DNS telemetry |
| CloudWatch Logs | Application / system logs | CloudWatch → SIEM connector | Custom application telemetry |
| AWS Config | Resource configuration changes | S3 / SNS → SIEM | Configuration drift detection |
| Security Hub | Aggregated findings | EventBridge → SIEM | Consolidated security findings |

---

## 11. Quality checklist

- [ ] CloudTrail data event logging requirement declared (S3, Lambda, DynamoDB).
- [ ] `userIdentity.type` used to distinguish Root/IAMUser/AssumedRole/FederatedUser/AWSService.
- [ ] Assume-role chains traced via `sessionContext.sessionIssuer` (not just `userIdentity.arn`).
- [ ] `sourceIPAddress` checked — `AWS Internal` = service-initiated, not user action.
- [ ] `errorCode` = `AccessDenied` correlated with expected permissions (distinguish SCP enforcement from privilege probing).
- [ ] `readOnly` field used to separate reconnaissance (read) from mutation (write) events.
- [ ] Defence impairment events monitored: `StopLogging`, `DeleteTrail`, `PutEventSelectors`, `DeleteDetector`, `DeleteFlowLogs`.
- [ ] Cross-account access patterns documented — `userIdentity.accountId` != resource account.
- [ ] GuardDuty finding types mapped to detection coverage gaps.
- [ ] S3 public access detections cover bucket policy, ACL, and Block Public Access settings.
- [ ] Snapshot sharing detections cover EBS, RDS, AMI, and Redshift.
- [ ] IAM privilege escalation paths (PassRole, policy manipulation, credential creation) monitored.
- [ ] Organisation-level operations (SCP changes, delegated admin) monitored if AWS Organizations is in use.
- [ ] Lambda/serverless function creation and code updates monitored.
- [ ] Security group changes allowing 0.0.0.0/0 inbound flagged.
- [ ] Root account usage always generates high-severity alerts.
