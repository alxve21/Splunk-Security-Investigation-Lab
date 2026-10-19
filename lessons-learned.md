# Lessons Learned

- Filter by a bounded time range and confirm the log source before interpreting events.
- Check field names and missing values in the actual results.
- Use `stats` and `timechart` to summarize, then inspect raw events to retain context.
- Compare 4625 and 4624 carefully; a nearby success is not proof of compromise or shared attribution.
- Keep Sysmon Event ID 1 process and parent context together.
- Describe saved searches and alerts only to the level actually configured and reviewed.
- Missing events may reflect collection, audit-policy, or retention limits.
- Keep screenshots genuine and sanitized.

## Current limits

This is introductory SPL and local Windows telemetry review. It does not claim advanced detection engineering, dashboards, malware analysis, or production SOC experience. Deeper SPL syntax revision is intentionally parked for later.
