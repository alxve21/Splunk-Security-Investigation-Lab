# Investigation 01 — Failed Login Hunt

**Scope:** Review Windows Security failures (EventCode 4625) in the local Splunk lab. This standalone case assumes no event count, source address, or outcome.

## Scenario

Assess whether observed 4625 events show repeated failures from a source and whether the pattern fits authorized activity. A cluster can justify investigation; it does not alone prove password spraying or compromise.

## Detection and search

```spl
source="WinEventLog:Security" EventCode=4625
```

For source-address aggregation:

```spl
source="WinEventLog:Security" EventCode=4625
| stats count by Source_Network_Address
| sort - count
```

Set a bounded time range. Field availability depends on the event rendering and inputs.

## Investigation

Review event time, target account, source address, host, logon type, and failure status/substatus. Compare with known authorized lab activity. If relevant, check for a nearby 4624 success from the same source and target; do not assume one occurred.

## Findings and disposition

**Observed result:** Pending local review. Record actual values and the search window below. Close as expected only with supporting context.

| Evidence field | Observed value |
|---|---|
| Time range and timezone | Pending |
| Host and target account(s) | Pending |
| Source address(es) | Pending |
| Event count / distinct accounts | Pending |
| Related 4624 reviewed? | Pending |
| Analyst disposition and rationale | Pending |

## MITRE ATT&CK

Password spraying (T1110.003) is a possible mapping only if the observed pattern supports it.

## Evidence placeholder

Add genuine Splunk search/result screenshots under `../screenshots/` after review. Redact identifying details.
