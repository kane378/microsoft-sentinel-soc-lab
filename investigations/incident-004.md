\# Incident Investigation: Multiple Failed Windows Logins



\## Incident Overview



\- Incident Number: 4

\- Detection Rule: `SOC - Multiple Failed Windows Logins`

\- Severity: Medium

\- Status: New

\- Detection Type: Multiple failed authentication attempts

\- Windows Event ID: 4625

\- MITRE ATT\&CK: T1110 - Brute Force



\## Alert Summary



The Sentinel Analytics Rule detected multiple Windows Security Event ID 4625 events within the configured detection window.



Event ID 4625 indicates that an account failed to log on.



The detection threshold was:



\*\*5 or more failed authentication attempts within 10 minutes.\*\*



\## Affected Host



The detected activity originated from the monitored Windows endpoint:



`DESKTOP-00BENSL`



\## Investigation Timeline



The investigation confirmed that multiple Event ID 4625 events were generated within a short period.



The observed test activity included repeated authentication failures against the temporary `SentinelTest` account.



The events were successfully collected through Azure Monitor Agent and ingested into the Log Analytics workspace.



\## Investigation Query



```kql

Event

| where TimeGenerated > ago(30m)

| where EventLog == "Security"

| where EventID == 4625

| project TimeGenerated, Computer, EventID, RenderedDescription

| order by TimeGenerated desc

