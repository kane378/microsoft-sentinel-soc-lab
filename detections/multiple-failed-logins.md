\# Detection: Multiple Failed Windows Logins



\## Objective



Detect repeated failed authentication attempts against a Windows endpoint.



\## Data Source



\- Platform: Windows 11

\- Log Source: Windows Security Event Log

\- Sentinel Table: `Event`

\- Event ID: `4625`

\- Event Description: An account failed to log on



\## Detection Logic



The detection searches the previous 10 minutes for Event ID 4625 events and counts failures for each computer.



Alert condition: \*\*5 or more failed authentication attempts within 10 minutes.\*\*



\## KQL



```kql

Event

| where TimeGenerated > ago(10m)

| where EventLog == "Security"

| where EventID == 4625

| summarize FailedAttempts = count(),

&#x20;           FirstSeen = min(TimeGenerated),

&#x20;           LastSeen = max(TimeGenerated)

&#x20;   by Computer

| where FailedAttempts >= 5

| project FirstSeen, LastSeen, Computer, FailedAttempts

| order by FailedAttempts desc

