# Investigation 03 — PowerShell Process Hunt

**Scope:** Review selected PowerShell process-creation telemetry from the local Sysmon feed. This is a filtered sample, not a claim that malware was found.

## Scenario

Review executable, user, command line, and parent process for PowerShell starts. Process context is a lead for triage, not a verdict.

## Search

~~~spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe"
| table _time, User, Image, ParentImage, CommandLine, ParentCommandLine
| sort _time
~~~

The captured seven-day screenshot uses a narrower filter: PowerShell image, excludes the Splunk PowerShell process, requires a Wazuh agent parent, deduplicates by CommandLine, and displays 8 rows. That filtered result should not be interpreted as the full volume of PowerShell activity.

## Investigation

Inspect image path, user, parent/child lineage, command context, and surrounding collected events. The captured process image is under the Windows PowerShell path and its visible parent image is the Wazuh agent. The visible command lines perform local account or security-policy checks. User and host result fields are redacted. The screenshot does not display ParentCommandLine.

## Findings and disposition

**Observed result:** Eight rows remain after the captured search deduplicates by command line. The available screenshot presents this as process telemetry; it does not establish intent, impact, or unauthorized execution.

| Evidence field | Observed value |
|---|---|
| Time range / host / user | Last 7 days as displayed; host and user redacted |
| Image and parent image | PowerShell executable under C:\Windows\SysWOW64\WindowsPowerShell\v1.0; parent shown as Wazuh agent executable under C:\Program Files (x86)\ossec-agent |
| Command-line context | Visible commands perform local account or security-policy checks; ParentCommandLine is not shown |
| Related telemetry | Only the filtered Sysmon EventCode 1 results in the screenshot are evidenced |
| Disposition and rationale | No malicious behavior is established. Verify the activity against authorized lab/agent configuration and inspect the underlying events if making a security decision. |

## MITRE ATT&CK

No technique is assigned from this screenshot. PowerShell (T1059.001) requires behavior-specific evidence and does not imply malicious use by itself.

## Evidence

![Filtered Sysmon PowerShell process search with command lines](../screenshots/powershell-sysmon-search.jpg)
