# RBA_RR - WIN base64 encoded powershell payload

## Metadata
| Field | Value |
| --- | --- |
| UUID | `0be66eea-4ae4-4544-811b-52651e20d744` |
| Schema | `rule::1.0` |
| Version | `6` |
| Created | `2024-05-16` |
| Modified | `2026-06-22` |
| TLP | clear (`TLP:CLEAR`) |
| Author | ec-digit-catch@ec.europa.eu |

## References
### Public
- **1**: [https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/PowerShellEncodedReconActivities.md](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/PowerShellEncodedReconActivities.md)
- **2**: [https://kqlquery.com/posts/hunting-encoded-powershell/](https://kqlquery.com/posts/hunting-encoded-powershell/)
- **3**: [https://github.com/Javelinblog/PowerShell-Encoded-Commands-Tool/tree/main?tab=readme-ov-file](https://github.com/Javelinblog/PowerShell-Encoded-Commands-Tool/tree/main?tab=readme-ov-file)

## Description
Detect base64 encoded PowerShell payload that could be used to launch 
a process or a script.
The detection applies up to 2 levels of encoded payload (a first payload 
containing a PowerShell command with a second base64 payload).  

### Splunk(Sentinel) investigation guidelines ###

The alert notification contains
- host(src_host): the host on which the process was launched.
- src_user: the account used.
- ParentProcessName(parent_process): the process launching the PS with base64 payload.
- NewProcessName(process): PS.
- CommandLine(command_line): the original command line as seen in logs.
- payload_b64_ascii [and payload_b64]: the first level of encoded payload. 
They are always present.
- payload_level2_b64_ascii [and payload_level2_b64] may also be provided 
if the first level was containing another base64 encoded payload.
For Sentinel Alert, you have to decode the base64 string present in command_line field,
using CyberChef or any base64 decoding tool.  

### SENTINEL alerts triage ###
CATCH uses TIDE_LD_005_CSIRC_WL_Win_Base64_Encoded_PS_Payload.csv
to filter legitimate or benign base64 encoded payloads used by PowerShell 
on EC Windows devices running on our Azure IaaS & PaaS tenant.

### ES-SPLUNK alerts triage ###
CATCH uses SOC_LT_289_WIN_reviewed_base64_encoded_payload-exclude.csv
to filter legitimate or benign base64 encoded payloads used by PowerShell 
on EC Windows devices.

## Status
| Field | Value |
| --- | --- |
| Status | `STAGING` |
| Severity | `Informational` |

## Detection model
- **Objective**: [Powershell encoded payload to start new process](../objectives/powershell-encoded-payload-to-start-new-process.md) (`bfeb24bf-8a17-4ccc-8aec-91721743153d`)

## Response

- **Alert severity**: High

## Platform configurations
<details><summary>sentinel</summary>

- **Enabled**: `True`
- **Status**: `PRODUCTION`
- **Entity mapping**: Process: CommandLine -> command_line
- **Entity mapping**: Host: HostName -> src_host, DnsDomain -> src_nt_domain
- **Entity mapping**: Account: Name -> src_user

```sql
let Base64EncodedPS = (
_GetWatchlist('CSIRC_WL_005')
| project command_line);
SecurityEvent
//we look for process creation
| where EventID==4688 
| where isnotempty(CommandLine)
//field renaming
    | extend command_line = CommandLine
    | extend src_host = tostring(split(Computer, '.', 0)[0])
    | extend src_user = SubjectUserName
    | extend src_nt_domain = tostring(strcat_array(array_slice(split(Computer, '.'), 1, -1), '.'))
    | extend user_type = AccountType
    | extend event_source = EventSourceName
    | extend signature = Activity
    | extend process = NewProcessName
    | extend parent_process = ParentProcessName
    | extend subscription_temp = split(_ResourceId, "/subscriptions/")[1]
    | extend subscription_id = split(subscription_temp, "/")[0]
//^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$
| where (command_line has "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" or command_line has "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe") and (command_line has "-e" or command_line has "-enc" or command_line has "-EncodedCommand")
| where parent_process !contains "C:\\Packages\\Plugins\\Microsoft.GuestConfiguration.ConfigurationforWindows\\"
| where command_line <> "\"C:\\windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe\" -noninteractive -outputFormat xml -NonInteractive -encodedCommand IABbAEUAbgB2AGkAcgBvAG4AbQBlAG4AdABdADoAOgBPAFMAVgBlAHIAcwBpAG8AbgAuAFYAZQByAHMAaQBvAG4AIAA= -inputFormat xml"
| where command_line !in~ (Base64EncodedPS)
| project
    TimeGenerated,
    src_host,
    command_line,
    src_user,
    src_nt_domain,
    user_type,
    signature,
    process,
    parent_process,
    subscription_id
| extend description = strcat("command_line=\"",command_line,"\" src_host=\"",src_host,"\" src_user=\"",src_user,"\" user_type=\"",user_type,"\" signature=\"",signature,"\" src_nt_domain=\"",src_nt_domain,"\" process=\"",process,"\" parent_process=\"",parent_process,"\" alert_description=\" suspicious bases64 encoded PowerShell Payload launched by ",src_user," from ",src_host,"\"")
```


</details>

<details><summary>splunk</summary>

- **Enabled**: `True`
- **Status**: `PRODUCTION`

```sql
`win_security_logs` 
    AND TERM(EventID=4688)
    AND NewProcessName IN ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe")
    AND ( TERM(C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\PowerShell.exe) OR TERM(C:\\WINDOWS\\sysWOW64\\WindowsPowerShell\\v1.0\\PowerShell.exe) )
    AND (TERM(-e) OR TERM(-enc) OR TERM(-EncodedCommand)) 
    NOT TERM(C:\\Windows\\CCM\\CcmExec.exe) 
| rex field=CommandLine "(?i)\s+(-e|-enc|-EncodedCommand)\s+(?<payload_b64>(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)" 
| where isnotnull(payload_b64) 
| search `exclude(SOC_LT_289_WIN_reviewed_base64_encoded_payload)` 
| `soc_macro_decode_b64(payload_b64)` 
| fields host, ParentProcessName, src_user, payload_b64_ascii, payload_b64, NewProcessName, CommandLine, _time 
| stats count min(_time) as et, max(_time) as lt, values(ParentProcessName) as ParentProcessName, values(payload_b64_ascii) as payload_b64_ascii, values(payload_b64) as payload_b64 by host src_user NewProcessName CommandLine 
| fields host, count, et, lt, ParentProcessName, src_user, payload_b64_ascii, payload_b64, NewProcessName, CommandLine 
| rename payload_* as payloadlevel1_* 
| rex field=payloadlevel1_b64_ascii "(?i)\s?(-e|-enc|-EncodedCommand)\s?(?<payload_b64>(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)$" 
| search `exclude(SOC_LT_289_WIN_reviewed_base64_encoded_payload)` 
| `soc_macro_decode_b64(payload_b64)` 
| rename payload_* as payload_level2_*, payloadlevel1_* as payload_* 
| rex field=payload_level2_b64_ascii "(?i)\s?(-e|-enc|-EncodedCommand)\s?(?<payload_level3_b64>(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)$" 
| eval payload_b64_ascii_sanitized=replace(payload_b64_ascii,"\s+\\\"[^\\\"]+\\\"\s+"," ") 
| lookup SOC_LD_339_RBA_powershell_watch_list_risk_score risk_object_command as payload_b64_ascii_sanitized output comment_description as matching_pattern, risk_confidence, trigger_notable 
| eval payload_level2_b64_ascii_sanitized=replace(payload_level2_b64_ascii,"\s+\\\"[^\\\"]+\\\"\s+"," ") 
| lookup SOC_LD_339_RBA_powershell_watch_list_risk_score risk_object_command as payload_level2_b64_ascii_sanitized outputnew comment_description as matching_pattern, risk_confidence, trigger_notable 
| eval RBA_RR_trigger_notable=if(isnotnull(payload_level3_b64) OR trigger_notable==1, 1, null()) 
| eval risk_score_default=10 
| eval risk_score=if(isnotnull(risk_confidence),max(risk_confidence),risk_score_default) 
| eval matching_pattern=if(isnotnull(matching_pattern),matching_pattern,"UNLISTED") 
| fields host, count, RBA_RR_trigger_notable, risk_score, matching_pattern, et, lt, ParentProcessName, src_user, payload_b64_ascii, payload_b64, payload_level2_b64_ascii, payload_level2_b64, NewProcessName, CommandLine, _time 
| `soc_macro_ctime_utc(et)` 
| `soc_macro_ctime_utc(lt)`
```


</details>

## Coverage
```mermaid
flowchart TB
subgraph "Objectives"
bfeb24bf_8a17_4ccc_8aec_91721743153d(["Powershell encoded<br>payload to start new<br>process"])
end
subgraph "Threats"
bdc58fee_8da6_4fc9_8fbd_30f8fd156bc7{{"Powershell with encoded<br>payload passed to<br>cmdline"}}
end
subgraph "Signals"
cf9c69a2_9317_4f0f_9506_fbeeb1c73ff0(("Powershell encoded<br>payload to start new<br>process"))
end
0be66eea_4ae4_4544_811b_52651e20d744["RBA_RR - WIN base64<br>encoded powershell<br>payload"]
bdc58fee_8da6_4fc9_8fbd_30f8fd156bc7 -->|covers| bfeb24bf_8a17_4ccc_8aec_91721743153d
bfeb24bf_8a17_4ccc_8aec_91721743153d --> cf9c69a2_9317_4f0f_9506_fbeeb1c73ff0
bfeb24bf_8a17_4ccc_8aec_91721743153d -->|implements| 0be66eea_4ae4_4544_811b_52651e20d744
```
## Related objects
| Type | Name | Direction | Relation |
| --- | --- | --- | --- |
| Objective | [Powershell encoded payload to start new process](../objectives/powershell-encoded-payload-to-start-new-process.md) (`bfeb24bf-8a17-4ccc-8aec-91721743153d`) | Upstream | objective |
| Threat | [Powershell with encoded payload passed to cmdline](../threats/powershell-with-encoded-payload-passed-to-cmdline.md) (`bdc58fee-8da6-4fc9-8fbd-30f8fd156bc7`) | Upstream | threat |
