# Investigation 05 — Sysmon Process Context

**Scope:** Inspect Sysmon Event ID 1 fields in Splunk and retain process lineage. No suspicious process is assumed to have been found.

## Scenario

Review the user and parent process that started a process, plus the recorded command line. Process context supports triage but does not prove intent or impact.

## Search

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time, User, Image, ParentImage, CommandLine, ParentCommandLine
| sort _time
```

## Investigation

Confirm source, EventCode, time range, endpoint, user, image, parent image, and identifiers available. Compare context with authorized lab activity. Note missing fields; do not infer network or file activity absent from this dataset.

## Findings and disposition

**Observed result:** Pending local review.

| Evidence field | Observed value |
|---|---|
| Time range / endpoint / user | Pending |
| Process and parent images | Pending |
| Command-line fields | Pending |
| Collection limits | Pending |
| Analyst disposition | Pending |

## MITRE ATT&CK

No technique is assigned without behavior-specific evidence. Process creation is telemetry, not an ATT&CK finding by itself.

## Evidence placeholder

Add a genuine sanitized Event ID 1 search under `../screenshots/`.
