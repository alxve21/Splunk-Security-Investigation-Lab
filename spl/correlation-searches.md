# Basic Correlation SPL Notes

These examples capture introductory event comparison practiced in the lab. They are manual searches, not production detection rules.

## Compare authentication events

```spl
(EventCode=4625 OR EventCode=4624)
| table _time, EventCode, Account_Name, Source_Network_Address, Logon_Type
| sort _time
```

Use the same host, account, source, and bounded time range when evaluating whether events may be related. Temporal proximity alone does not prove causation or attribution.

## Analyst workflow

1. Confirm both event codes and Windows Security source are present.
2. Inspect raw details for the proposed account, host, source, and logon type.
3. Compare with authorized activity and note collection gaps.
4. Label what is confirmed, suspicious, or requires verification.

This is a search workflow, not automated correlation. Do not infer compromise or shared actor without corroborating evidence.
