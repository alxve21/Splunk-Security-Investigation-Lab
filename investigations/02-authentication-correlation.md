# Investigation 02 — Authentication Correlation

**Scope:** Compare Windows failed and successful logon events in a bounded range. Similarity in time or source is a triage lead, not proof of shared actor or cause.

## Scenario

Review whether the captured data includes nearby 4625 and 4624 activity, then validate candidate records individually before drawing conclusions.

## Search

~~~spl
(EventCode=4625 OR EventCode=4624)
| table _time, EventCode, Account_Name, Source_Network_Address, Logon_Type
| sort _time
~~~

Set a bounded time range and confirm the Windows Security source and actual field names. The screenshot is an aggregated ten-minute correlation view; it is not a raw event-pair report.

## Investigation

Review original timestamps, account, source, host, logon type, and status fields. Compare with authorized activity. A 4624 indicates a successful logon record only after validating its event context; it is not malicious by itself.

## Findings and disposition

**Observed result:** The captured 30-day view shows 8 qualifying ten-minute buckets containing both 4625 and 4624, with a later success timestamp in each bucket and the visible source 127.0.0.1. Account and host result values are redacted. A bucket can contain multiple events; these are temporal co-occurrence candidates, not 8 proven event pairs, sessions, or a demonstrated failure-then-success chain for one user.

| Evidence field | Observed value |
|---|---|
| Time range | Last 30 days as displayed in Splunk; timezone not visible |
| Host/account/source reviewed | Host and account redacted; visible source is loopback 127.0.0.1 |
| 4625 and 4624 observations | 8 displayed ten-minute buckets contain both codes and a later success timestamp |
| Correlation basis / limitations | Bucket-level co-occurrence. Must inspect underlying events for same account/host and exact order; source similarity does not attribute an actor. |
| Analyst disposition | Triage candidates only. No malicious activity, compromise, or attribution is established by this view. |

## MITRE ATT&CK

No technique is assigned. Valid Accounts (T1078) would require evidence of unauthorized account use.

## Evidence

![Thirty-day 4625 and 4624 temporal co-occurrence candidates](../screenshots/4625-4624-correlation.jpg)
