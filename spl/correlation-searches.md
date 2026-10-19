# Basic Correlation SPL Notes

These examples capture manual event comparison practiced in the local lab. They are triage searches, not production detection rules.

## Inspect authentication events

~~~spl
source="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| table _time, EventCode, Account_Name, Source_Network_Address, Logon_Type
| sort _time
~~~

Use a bounded time range and inspect the original events for host, account, source, and logon type.

## Captured ten-minute candidate aggregation

This is the query shown in the correlation screenshot. It groups by ten-minute bucket, account, source, and host; then compares the earliest failure with the latest success in each bucket. Account and host values are redacted in the displayed result.

~~~spl
source="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| eval failure_time=if(EventCode=4625,_time,null()), success_time=if(EventCode=4624,_time,null())
| bin _time span=10m
| stats min(failure_time) as failure_time max(success_time) as success_time values(EventCode) as EventCodes by _time Account_Name Source_Network_Address host
| where isnotnull(failure_time) AND isnotnull(success_time) AND success_time>failure_time AND Source_Network_Address!="-"
| eval Account_Name="REDACTED", host="REDACTED"
| convert ctime(_time) ctime(failure_time) ctime(success_time)
| table _time EventCodes Account_Name Source_Network_Address host failure_time success_time
| sort 0 - success_time
~~~

A qualifying bucket is a candidate for event-level review, not proof of an individual event pair, session, shared actor, or compromise. Temporal proximity alone does not establish causation or attribution.

## Analyst workflow

1. Confirm both event codes and the Windows Security source are present.
2. Inspect raw details for the proposed account, host, source, and logon type.
3. Compare with authorized activity and note collection gaps.
4. Label what is confirmed, suspicious, or requires verification.

This is a manual search workflow, not automated correlation.
