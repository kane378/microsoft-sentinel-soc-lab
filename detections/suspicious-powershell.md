\# Detection: Suspicious PowerShell Execution



\## Objective



Detect PowerShell process execution on a Windows endpoint using Sysmon Process Creation events.



PowerShell is a legitimate Windows administration tool but can also be abused during attacks for execution, scripting, discovery, and other post-compromise activities.



\## Data Source



\- Platform: Windows 11

\- Log Source: Microsoft-Windows-Sysmon/Operational

\- Sentinel Table: `Event`

\- Event ID: `1`

\- Event Description: Process Create



\## Detection Logic



The detection searches Sysmon Event ID 1 records and extracts the actual process `Image` field.



The detection triggers when the process image ends with:



`powershell.exe`



\## KQL



```kql

Event

| where TimeGenerated > ago(6h)

| where EventLog == "Microsoft-Windows-Sysmon/Operational"

| where EventID == 1

| extend Image = extract(@"Image:\\s+(\[^\\s]+)", 1, RenderedDescription)

| where Image endswith "powershell.exe"

| project TimeGenerated, Computer, Image, RenderedDescription

| order by TimeGenerated desc

