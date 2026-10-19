# Investigation 02 — Authentication Correlation

**Scope:** Compare Windows failed and successful logon events in a bounded range. This case assumes no relationship between the two event types until verified.

## Scenario

Distinguish isolated failures from a pattern that includes a subsequent success. Timing or source similarity alone does not prove a shared actor or cause.

## Search

```spl
(EventCode=4625 OR EventCode=4624)
| table _time, EventCode, Account_Name, Source_Network_Address, Logon_Type
| sort _time
```

Set a bounded time range and confirm the Windows Security source and actual field names.

## Investigation

Review timestamps, account, source, host, logon type, and status fields. Compare with authorized activity. Treat a 4624 as an observed success only after confirming the record and its context; it is not malicious by itself.

## Findings and disposition

**Observed result:** Pending local review.

| Evidence field | Observed value |
|---|---|
| Time range and timezone | Pending |
| Host/account/source reviewed | Pending |
| 4625 and 4624 observations | Pending |
| Correlation basis / limitations | Pending |
| Analyst disposition | Pending |

## MITRE ATT&CK

Valid Accounts (T1078) is relevant only if evidence supports unauthorized use of an account.

## Evidence placeholder

Capture the local search and reviewed rows under `../screenshots/`, redacting identifying details.
