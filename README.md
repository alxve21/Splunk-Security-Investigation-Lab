# Splunk Security Investigation Lab

A practical lab portfolio covering Windows log review, authentication triage, Sysmon process context, and basic SPL correlation. Work was completed in a local Splunk Enterprise instance on Windows. This is training work, not production SOC experience.

## Lab coverage

- Splunk Enterprise at `localhost:8000`
- Windows Security, System, and Application logs searchable in the captured local window
- Sysmon Operational events collected through `inputs.conf`
- Windows Security Events **4625** (failed logon) and **4624** (successful logon)
- Sysmon Event **1** (process creation) and PowerShell process context
- SPL practice: `source`, `EventCode`, `OR`, `table`, `stats count by`, `sort`, `dedup`, `timechart`, `where`, wildcards, saved searches/alerts, and basic correlation

## Investigations

| Case | Focus |
| --- | --- |
| [01 — Failed login hunt](investigations/01-failed-login-hunt.md) | Review 4625 failures and source patterns |
| [02 — Authentication correlation](investigations/02-authentication-correlation.md) | Compare 4625 and 4624 context |
| [03 — PowerShell process hunt](investigations/03-powershell-process-hunt.md) | Search process telemetry and parent context |
| [04 — Event aggregation analysis](investigations/04-event-aggregation-analysis.md) | Aggregate observed events and examine time patterns |
| [05 — Sysmon process context](investigations/05-sysmon-process-context.md) | Inspect Event ID 1 process and command-line fields |

## SPL reference

- [Authentication searches](spl/authentication-searches.md)
- [Process searches](spl/process-searches.md)
- [Basic correlation searches](spl/correlation-searches.md)

## Repository map

- `investigations/` — case workflows, observations, evidence links, and limitations
- `spl/` — practiced SPL examples with field and time-range caveats
- [`screenshots/` evidence gallery](screenshots/README.md) — genuine local Splunk captures with captions
- [Lessons learned](lessons-learned.md)

## Evidence status

The gallery contains six genuine local Splunk screenshots captured on 2026-10-19. Search windows and result counts are point-in-time observations; host and account result fields are redacted where present. Loopback address `127.0.0.1` is retained because it is material to interpreting the local results. See the case pages for the exact scope and caveats. These captures do not evidence saved-search or alert configuration and do not establish malicious activity, compromise, or actor attribution.
