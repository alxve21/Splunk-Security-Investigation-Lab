# Process SPL Notes

The practiced search uses Sysmon Operational events ingested by local Splunk. Verify source and field names in local results.

## PowerShell process creation

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe"
| table _time, User, Image, ParentImage, CommandLine, ParentCommandLine
| sort _time
```

Review process lineage, user, executable path, and command context. Use a bounded range and redact sensitive arguments before screenshots. Event ID 1 indicates process creation telemetry, not malicious behavior.

## Broader process context

```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time, User, Image, ParentImage, CommandLine, ParentCommandLine
| sort _time
```

If fields are absent, document an input or field-extraction limitation instead of assuming values.
