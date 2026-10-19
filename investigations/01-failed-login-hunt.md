# Investigation 01 — Failed Login Hunt

**Scope:** Review Windows Security EventCode 4625 failures in the local Splunk lab. The findings below describe only the captured search windows and fields.

## Scenario

Assess whether observed failures cluster by source and whether context supports further review. A cluster alone does not prove password spraying or compromise.

## Detection and search

~~~spl
source="WinEventLog:Security" EventCode=4625
~~~

For source-address aggregation:

~~~spl
source="WinEventLog:Security" EventCode=4625
| stats count by Source_Network_Address
| sort - count
~~~

The screenshot search is bounded to the displayed last 7 days. Field availability depends on the event rendering and inputs.

## Investigation

Review event time, account, source address, host, logon type, and failure status/substatus in the raw records. Compare with authorized lab activity. A separate 30-day correlation view is documented in [Investigation 02](02-authentication-correlation.md); its ten-minute buckets are candidates for review, not proof that a particular success followed a particular failure.

## Findings and disposition

**Observed result:** The captured seven-day 4625 search returned 11 events. In the source aggregation, 8 were grouped under loopback address 127.0.0.1 and 3 under a missing address value. Account and host result fields are redacted. The screenshots do not establish distinct account count, a timezone, logon type, failure substatus, or an external source.

| Evidence field | Observed value |
|---|---|
| Time range | Last 7 days as displayed in Splunk; timezone not visible |
| Host and target account(s) | Redacted in the screenshots; distinct account count not established |
| Source address(es) | 127.0.0.1 (8); missing value (3) |
| Event count | 11 in the captured search |
| Related 4624 reviewed? | Separate 30-day bucket-level comparison is shown in case 02; individual event pairing is not established |
| Analyst disposition and rationale | Descriptive lab telemetry. No malicious activity, compromise, or actor attribution is established; review raw event context before any disposition. |

## MITRE ATT&CK

No technique is assigned from this evidence. Password spraying (T1110.003) would require a supported pattern and additional context.

## Evidence

The first image shows the bounded event search; the second shows its source aggregation.

![Captured Windows Security 4625 search](../screenshots/4625-search.jpg)

![Captured failed logons grouped by source address](../screenshots/failed-logins-by-source.jpg)
