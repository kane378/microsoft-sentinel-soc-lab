\# Microsoft Sentinel SOC Lab



\## End-to-End Windows SOC Monitoring, Detection Engineering \& Incident Investigation



A hands-on Security Operations Center (SOC) implementation using \*\*Microsoft Sentinel, Azure Arc, Azure Monitor Agent (AMA), Log Analytics, Windows Security Events, Sysmon, and KQL\*\*.



The project demonstrates an end-to-end security monitoring workflow starting from endpoint telemetry collection and continuing through detection engineering, alert generation, incident creation, investigation, and MITRE ATT\&CK mapping.



\---



\## 1. Project Overview



This project was developed as a practical SOC monitoring and detection engineering environment using a Windows 11 endpoint connected to Microsoft Azure.



The objective was to build and validate a pipeline capable of:



\- Collecting Windows Security Event Logs

\- Collecting Sysmon endpoint telemetry

\- Centralizing security data in Azure Log Analytics

\- Querying telemetry using Kusto Query Language (KQL)

\- Creating Microsoft Sentinel Analytics Rules

\- Generating security alerts

\- Automatically creating security incidents

\- Investigating incidents using KQL

\- Mapping detected behaviors to MITRE ATT\&CK

\- Refining detection logic to reduce false positives



The project was tested using controlled security activity on a dedicated Windows endpoint.



\---



\# 2. SOC Architecture



```mermaid

flowchart TD

&#x20;   A\[Windows 11 Endpoint]



&#x20;   A --> B\[Windows Security Event Logs]

&#x20;   A --> C\[Sysmon]



&#x20;   B --> D\[Azure Arc]

&#x20;   C --> D



&#x20;   D --> E\[Azure Monitor Agent - AMA]

&#x20;   E --> F\[Data Collection Rule]



&#x20;   F --> G\[Log Analytics Workspace]

&#x20;   G --> H\[Microsoft Sentinel]



&#x20;   H --> I\[KQL Detection]

&#x20;   I --> J\[Analytics Rules]



&#x20;   J --> K\[Security Alerts]

&#x20;   K --> L\[Security Incidents]



&#x20;   L --> M\[SOC Investigation]

&#x20;   M --> N\[MITRE ATT\&CK Mapping]

&#x20;   N --> O\[Analyst Conclusion \& Response]

End-to-End Flow

Windows Endpoint

&#x20;     ↓

Windows Security Events + Sysmon

&#x20;     ↓

Azure Arc

&#x20;     ↓

Azure Monitor Agent

&#x20;     ↓

Data Collection Rule

&#x20;     ↓

Log Analytics Workspace

&#x20;     ↓

Microsoft Sentinel

&#x20;     ↓

KQL

&#x20;     ↓

Analytics Rules

&#x20;     ↓

Security Alerts

&#x20;     ↓

Security Incidents

&#x20;     ↓

Investigation

&#x20;     ↓

MITRE ATT\&CK

3\. Environment

Component	Configuration

Endpoint	Windows 11

Endpoint Management	Azure Arc

Monitoring Agent	Azure Monitor Agent (AMA)

Collection	Data Collection Rule (DCR)

SIEM	Microsoft Sentinel

Log Storage	Azure Log Analytics

Query Language	Kusto Query Language (KQL)

Endpoint Telemetry	Sysmon

Security Framework	MITRE ATT\&CK

Azure Resources



The project uses:



Azure for Students subscription

Resource Group: sentinel-soc-lab

Log Analytics Workspace: sentinel-law

Region: Central India

Azure Arc connected Windows endpoint: DESKTOP-00BENSL

4\. Endpoint Onboarding



The Windows 11 endpoint was connected to Azure using Azure Arc.



Azure Arc allows the Windows machine to be represented and managed as an Azure resource even though the machine is not running as an Azure virtual machine.



The Azure Arc agent was successfully installed and the endpoint reported a connected state.



Endpoint

DESKTOP-00BENSL

Windows 11

Azure Arc: Connected

5\. Azure Monitor Agent



The Azure Monitor Agent (AMA) was installed on the Windows endpoint.



AMA is responsible for collecting the configured Windows telemetry and forwarding it according to the Data Collection Rule.



The installed AMA extension was successfully reported as running on the endpoint.



6\. Data Collection Rule



A Data Collection Rule named:



sentinel-windows-security



was configured to collect Windows event logs.



The destination was:



sentinel-law

Windows Security Events



The DCR was configured to collect Windows Security events including authentication-related activity.



One of the primary events used in this project was:



Event ID 4625

An account failed to log on

Sysmon



The DCR was later modified to use custom Windows Event Log collection so that Sysmon telemetry could also be collected.



The Sysmon channel configured was:



Microsoft-Windows-Sysmon/Operational



This enabled the project to collect Sysmon Process Creation events.



7\. Telemetry Validation



After configuring Azure Arc, AMA, and the DCR, telemetry was validated directly in Log Analytics.



AMA Heartbeat



The following KQL query was used to verify that the Azure Monitor Agent was communicating with Azure:



Heartbeat

| where TimeGenerated > ago(30m)

| project TimeGenerated, Computer, Category, OSType

| order by TimeGenerated desc



Heartbeat events confirmed that the endpoint and AMA pipeline were operational.



8\. Windows Security Event Monitoring



Initially, the expected SecurityEvent table did not return the required results.



Instead of assuming that ingestion was broken, the generic Event table was investigated.



The following query confirmed that Windows Security events were arriving:



Event

| where TimeGenerated > ago(30m)

| where EventLog == "Security"

| project TimeGenerated, Computer, EventID, RenderedDescription

| order by TimeGenerated desc



This confirmed that Windows Security events were being successfully ingested.



9\. Event ID 4625 Detection



Event ID 4625 represents a failed Windows authentication attempt.



A controlled authentication test was performed using a temporary local test account.



The generated Event ID 4625 events were successfully:



Windows

&#x20;  ↓

AMA

&#x20;  ↓

Log Analytics

&#x20;  ↓

KQL



The telemetry was then used to build an automated Sentinel detection.



10\. Sysmon Integration



Sysmon was installed on the Windows endpoint to provide additional endpoint visibility.



The Sysmon installation was verified using:



Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5



The endpoint generated Sysmon events including:



Event ID 1 - Process Create

Event ID 5 - Process Terminated



The DCR was then updated to collect:



Microsoft-Windows-Sysmon/Operational



Sysmon Event ID 1 telemetry was successfully observed in Log Analytics.



11\. Detection Engineering



Two primary Microsoft Sentinel Analytics Rules were implemented.



Detection 1 — Multiple Failed Windows Logins

Rule

SOC - Multiple Failed Windows Logins

Purpose



Detect repeated failed authentication attempts that may indicate password guessing or brute-force behavior.



Configuration

Property	Value

Event	4625

Severity	Medium

Tactic	Credential Access

Technique	T1110 - Brute Force

Detection Window	10 minutes

Threshold	5 or more failures

Frequency	5 minutes

Incident Creation	Enabled

KQL

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

12\. Detection 2 — Suspicious PowerShell Execution

Rule

SOC - Suspicious PowerShell or Command Shell Execution

Purpose



Detect PowerShell execution using Sysmon Process Creation telemetry.



PowerShell is a legitimate administration tool but can also be abused during attacks.



Configuration

Property	Value

Event	Sysmon Event ID 1

Severity	Medium

Tactic	Execution

Technique	T1059 - Command and Scripting Interpreter

Sub-technique	T1059.001 - PowerShell

Incident Creation	Enabled

KQL

Event

| where TimeGenerated > ago(6h)

| where EventLog == "Microsoft-Windows-Sysmon/Operational"

| where EventID == 1

| extend Image = extract(@"Image:\\s+(\[^\\s]+)", 1, RenderedDescription)

| where Image endswith "powershell.exe"

| project TimeGenerated, Computer, Image, RenderedDescription

| order by TimeGenerated desc

13\. Detection Refinement and False-Positive Analysis



During testing, the initial PowerShell detection searched the entire Sysmon event description:



RenderedDescription has\_any ("powershell.exe", ...)



This could produce false positives because powershell.exe could appear in fields such as ParentImage.



For example, a conhost.exe process could have PowerShell as its parent process and therefore contain the string powershell.exe in the event description.



The detection was refined to extract the actual process Image field:



| extend Image = extract(@"Image:\\s+(\[^\\s]+)", 1, RenderedDescription)

| where Image endswith "powershell.exe"



This ensures that the process being detected is actually PowerShell rather than simply a process launched by PowerShell.



This refinement demonstrates an important SOC detection engineering principle:



Detection logic should be validated against process context to reduce false positives.



14\. Analytics Rule → Alert → Incident



The Analytics Rules were tested using controlled activity.



The complete detection pipeline was successfully validated:



Endpoint Event

&#x20;     ↓

AMA

&#x20;     ↓

Log Analytics

&#x20;     ↓

KQL

&#x20;     ↓

Sentinel Analytics Rule

&#x20;     ↓

Security Alert

&#x20;     ↓

Security Incident

PowerShell Detection



Controlled PowerShell execution generated Sysmon Event ID 1 telemetry.



The corresponding Sentinel detection generated security alerts and incidents.



Failed Login Detection



Controlled failed authentication activity generated multiple Event ID 4625 events.



The Sentinel Analytics Rule detected the threshold and generated security alerts.



A Sentinel security incident was subsequently created.



15\. Incident Investigation



A generated failed-login incident was investigated using KQL.



Incident

Incident Number: 4

Title: SOC - Multiple Failed Windows Logins

Severity: Medium

Status: New

Investigation Query

Event

| where TimeGenerated > ago(30m)

| where EventLog == "Security"

| where EventID == 4625

| project TimeGenerated, Computer, EventID, RenderedDescription

| order by TimeGenerated desc

Aggregation

Event

| where TimeGenerated > ago(30m)

| where EventLog == "Security"

| where EventID == 4625

| summarize FailedAttempts = count(),

&#x20;           FirstSeen = min(TimeGenerated),

&#x20;           LastSeen = max(TimeGenerated)

&#x20;   by Computer

| order by FailedAttempts desc



The investigation confirmed multiple failed authentication events on:



DESKTOP-00BENSL



The activity satisfied the detection threshold.



16\. Analyst Assessment



The failed-login activity was intentionally generated as part of a controlled SOC detection test.



A temporary local test account was used to produce authentication failures.



Therefore:



Detection: Validated

Activity: Controlled Test

Confirmed Attack: No



The incident demonstrates that the detection mechanism can identify repeated authentication failures, but the test itself should not be classified as a real brute-force attack.



In a production environment, additional investigation would be required before determining malicious intent.



17\. MITRE ATT\&CK Mapping



The detections were mapped to MITRE ATT\&CK techniques.



Detection	MITRE ATT\&CK

Multiple Failed Windows Logins	T1110 - Brute Force

Suspicious PowerShell	T1059 - Command and Scripting Interpreter

PowerShell	T1059.001 - PowerShell



MITRE ATT\&CK mapping provides a standardized way to describe the adversary behaviors represented by the detections.



18\. SOC Investigation Methodology



When a detection triggers, the analyst should follow a structured investigation process.



Step 1 — Identify the Host



Determine which endpoint generated the activity.



Step 2 — Identify the Account or Process



For authentication detections, identify the targeted account.



For process detections, identify the executable and user context.



Step 3 — Establish a Timeline



Review:



First occurrence

Last occurrence

Number of events

Related activity before and after the detection

Step 4 — Review Related Events



Search for:



Successful logons

Additional failed logons

Process creation

PowerShell activity

Related endpoint activity

Step 5 — Determine Intent



Classify the activity as:



Expected

Suspicious

Malicious

Controlled testing

Step 6 — Map to MITRE ATT\&CK



Map confirmed behavior to an appropriate ATT\&CK technique.



Step 7 — Respond



Depending on the findings, response actions may include:



Credential protection

Account investigation

Endpoint isolation

Process termination

Further threat hunting

Escalation

19\. KQL Repository



The kql/ directory contains the queries used during detection and investigation.



kql/

├── failed-login-detection.kql

├── powershell-detection.kql

└── investigation-queries.kql



These queries can be imported or adapted for future Sentinel investigations.



20\. Repository Structure

microsoft-sentinel-soc-lab/

│

├── README.md

│

├── architecture/

│   └── sentinel-soc-architecture.md

│

├── kql/

│   ├── failed-login-detection.kql

│   ├── powershell-detection.kql

│   └── investigation-queries.kql

│

├── detections/

│   ├── multiple-failed-logins.md

│   └── suspicious-powershell.md

│

├── investigations/

│   └── incident-004.md

│

└── screenshots/

&#x20;   └── project evidence

21\. Project Evidence



The screenshots/ directory contains selected implementation and validation evidence.



Evidence includes:



Azure subscription

Resource Group

Log Analytics Workspace

Microsoft Sentinel

Azure Arc

Azure Monitor Agent

Data Collection Rule

Sysmon

Windows Security Events

Event ID 4625

Sysmon Event ID 1

KQL queries

Analytics Rules

Security Alerts

Security Incidents

MITRE ATT\&CK mapping



Screenshots are provided to demonstrate the actual implementation and validation of the SOC pipeline.



22\. Microsoft Defender Portal Limitation



During testing, the Microsoft Sentinel Analytics and Incidents experiences intermittently redirected to the Microsoft Defender portal with the message:



This page was moved to the Microsoft Defender portal.



The behavior was inconsistent: the pages sometimes loaded correctly and sometimes redirected back to the Defender SIEM Workspaces/settings area.



Importantly, the underlying Sentinel backend continued to function.



Telemetry ingestion, KQL queries, Analytics Rules, security alerts, and security incident generation were independently validated through Log Analytics and Sentinel queries.



Therefore, the portal behavior did not prevent validation of the underlying SOC detection pipeline.



23\. Security Considerations



This project was designed as a controlled security lab.



Testing Scope



Testing was performed against a controlled Windows endpoint.



A temporary local test account was used when generating failed authentication events.



Credentials



No passwords, API keys, access tokens, or cloud credentials should be stored in this repository.



Controlled Activity



The generated PowerShell and authentication activity was performed for detection validation and should not be interpreted as evidence of an actual compromise.



24\. Lessons Learned



The project provided practical experience with:



Windows security telemetry

Endpoint monitoring

Azure Arc onboarding

Azure Monitor Agent

Data Collection Rules

Log Analytics

Microsoft Sentinel

KQL detection engineering

Security Event ID analysis

Sysmon telemetry

Alert and incident workflows

False-positive investigation

MITRE ATT\&CK mapping

SOC investigation methodology

Troubleshooting cloud-based security monitoring pipelines



A key lesson was that successful SOC monitoring requires validating every stage of the telemetry pipeline rather than assuming that an empty result means the data source is unavailable.



25\. Future Improvements



The current implementation can be extended with:



Additional Windows Security Event detections

More Sysmon event coverage

Automated MITRE ATT\&CK mapping

Threat intelligence enrichment

User and Entity Behavior Analytics

Automated incident summaries

Automated remediation recommendations

Advanced PowerShell detection

Network telemetry integration

Threat hunting queries

Automated response playbooks

Integration with additional security data sources

26\. Final Outcome



The project successfully demonstrated an end-to-end SOC monitoring and detection workflow:



Windows 11

&#x20;   ↓

Azure Arc

&#x20;   ↓

Azure Monitor Agent

&#x20;   ↓

Data Collection Rule

&#x20;   ↓

Log Analytics

&#x20;   ↓

Microsoft Sentinel

&#x20;   ↓

KQL

&#x20;   ↓

Analytics Rules

&#x20;   ↓

Security Alerts

&#x20;   ↓

Security Incidents

&#x20;   ↓

Investigation

&#x20;   ↓

MITRE ATT\&CK

Key Results

Windows endpoint successfully onboarded.

Windows Security telemetry successfully collected.

Sysmon successfully integrated.

Event ID 4625 successfully detected.

Sysmon Event ID 1 successfully detected.

KQL detections developed and tested.

False-positive detection logic refined.

Sentinel Analytics Rules created.

Security alerts successfully generated.

Security incidents successfully generated.

Incident investigation performed.

MITRE ATT\&CK techniques mapped.

End-to-end SOC detection pipeline validated.

