# Investigation 03 — PowerShell Process Hunt

**Scope:** Review PowerShell process-creation telemetry. This case does not claim malware execution.

## Scenario

Review executable, user, command line, and parent process for a PowerShell start. A process or encoded-looking argument is a lead, not a verdict.

## Search

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe"
| table _time, User, Image, ParentImage, CommandLine, ParentCommandLine
| sort _time
```

Set a bounded range and verify field names in local results.

## Investigation

Inspect image path, user, parent/child lineage, command context, and surrounding collected events. Compare with known authorized activity. Redact sensitive arguments before public screenshots.

## Findings and disposition

**Observed result:** Pending local review.

| Evidence field | Observed value |
|---|---|
| Time range / host / user | Pending |
| Image and parent image | Pending |
| Command-line context | Pending |
| Related telemetry | Pending |
| Disposition and rationale | Pending |

## MITRE ATT&CK

PowerShell (T1059.001) is conditional on verified behavior and does not establish malicious use.

## Evidence placeholder

Add a genuine sanitized search and event view under `../screenshots/`.
