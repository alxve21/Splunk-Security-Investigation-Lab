# Authentication SPL Notes

These examples reflect SPL practiced against the local Windows event dataset. Select a bounded time range and verify field names in the actual results; no counts or alert outcomes are implied.

## Failed logons

```spl
source="WinEventLog:Security" EventCode=4625
```

## Aggregate failures by source

```spl
source="WinEventLog:Security" EventCode=4625
| stats count by Source_Network_Address
| sort - count
```

Review null values, host scope, and raw events before interpreting an aggregate. A source with failures is not automatically an attacker.

## Compare failures and successes

```spl
(EventCode=4625 OR EventCode=4624)
| table _time, EventCode, Account_Name, Source_Network_Address, Logon_Type
| sort _time
```

Add the Security source filter if needed based on actual inputs. A success is an observation requiring context.
