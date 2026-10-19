# Investigation 05 — Sysmon Process Context

**Scope:** Review the process and parent fields visible in the local Sysmon Event ID 1 PowerShell sample. The evidence is limited to the captured filtered view.

## Scenario

Use process creation fields to retain basic lineage and command context. Process telemetry supports triage but does not prove intent or impact.

## Search

~~~spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time, User, Image, ParentImage, CommandLine
| sort _time
~~~

The screenshot uses a narrower seven-day search for PowerShell processes, excludes the Splunk PowerShell process, requires a Wazuh agent parent, and deduplicates by CommandLine. See [Investigation 03](03-powershell-process-hunt.md) for the observed command context.

## Investigation

Confirm source, EventCode, time range, endpoint, user, image, parent image, and command fields available. Compare context with authorized lab activity. Do not infer network or file activity that is absent from this dataset.

## Findings and disposition

**Observed result:** The captured view shows eight rows after deduplicating by command line. The PowerShell image is parented by the Wazuh agent. User and host fields are redacted. Visible child command lines perform local account or security-policy checks.

| Evidence field | Observed value |
|---|---|
| Time range / endpoint / user | Last 7 days as displayed; endpoint and user redacted |
| Process and parent images | PowerShell executable under C:\Windows\SysWOW64\WindowsPowerShell\v1.0; parent shown as Wazuh agent executable under C:\Program Files (x86)\ossec-agent |
| Command-line context | Child command line is visible in the linked capture |
| Collection limits | Filtered PowerShell subset only; does not represent all Event ID 1 events or all process types |
| Analyst disposition | No suspicious behavior is established by these fields. Validate activity against authorized agent configuration and underlying events before making a security determination. |

## MITRE ATT&CK

No technique is assigned without behavior-specific evidence. Process creation is telemetry, not an ATT&CK finding by itself.

## Evidence

![Filtered Sysmon PowerShell process search showing process and parent image context](../screenshots/powershell-sysmon-search.jpg)
