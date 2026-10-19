# Authentication and Source SPL Notes

These examples reflect SPL captured or practiced against the local Windows event dataset. Select a bounded time range and verify field names in the actual results; counts are point-in-time and no alert outcome is implied.

## Verify Windows event source coverage

This is the source summary query shown in the last-24-hour evidence capture. The host is replaced with a redaction label in the results.

~~~spl
source="WinEventLog:Security" OR source="WinEventLog:System" OR source="WinEventLog:Application"
| eval host="REDACTED"
| stats count by source sourcetype host
| sort - count
~~~

The displayed result confirms searchable records for those sources in the selected window; it does not prove complete collection or retention.

## Failed logons

~~~spl
source="WinEventLog:Security" EventCode=4625
~~~

## Aggregate failures by source

This version normalizes the missing address value as shown in the evidence screenshot.

~~~spl
source="WinEventLog:Security" EventCode=4625
| eval Source_Network_Address=if(isnull(Source_Network_Address) OR Source_Network_Address="-","(missing)",Source_Network_Address)
| stats count by Source_Network_Address
| sort - count
~~~

Review missing values, host scope, and raw events before interpreting an aggregate. A source with failures is not automatically an attacker.

## Compare failures and successes

~~~spl
source="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| table _time, EventCode, Account_Name, Source_Network_Address, Logon_Type
| sort _time
~~~

A success is an observation requiring context. For the captured ten-minute candidate aggregation, see [the correlation SPL notes](correlation-searches.md).
