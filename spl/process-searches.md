# Process SPL Notes

The practiced search uses Sysmon Operational events searchable in the local Splunk feed. Verify source and field names in local results.

## PowerShell process creation

~~~spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe"
| table _time, User, Image, ParentImage, CommandLine
| sort _time
~~~

The evidence screenshot uses a narrower filter: it excludes the Splunk PowerShell process, requires a Wazuh agent parent, deduplicates by command line, and displays 8 rows. Review process lineage, user, executable path, and command context. Use a bounded range and redact sensitive arguments before screenshots. Event ID 1 indicates process creation telemetry, not malicious behavior.

## Broader process context

~~~spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| table _time, User, Image, ParentImage, CommandLine
| sort _time
~~~

If a field is absent from local results, document the input or field-extraction limitation instead of assuming a value.
