# 🛡️ Microsoft Sentinel SOC Lab

### 🔎 End-to-End Windows Security Monitoring, Detection & Incident Investigation

A practical Security Operations Center (SOC) lab built using **Microsoft Azure, Microsoft Sentinel, Azure Arc, Azure Monitor Agent (AMA), Data Collection Rules (DCR), Windows Security Logs, Sysmon, KQL, Analytics Rules, Security Alerts, Security Incidents, and MITRE ATT&CK**.

The project demonstrates how security telemetry can be collected from a Windows endpoint, centralized in Microsoft Sentinel, analyzed using KQL, and converted into actionable security alerts and incidents.

---

## 🎯 Project Objectives

The main objectives of this project are:

- 🖥️ Monitor a Windows 11 endpoint
- 🔗 Connect the endpoint to Azure using Azure Arc
- 📡 Install and configure Azure Monitor Agent (AMA)
- 📋 Configure Data Collection Rules (DCR)
- 📊 Send Windows security telemetry to Log Analytics
- 🛡️ Configure Microsoft Sentinel
- 🔎 Develop KQL detection queries
- 🚨 Create Sentinel Analytics Rules
- 📌 Generate and investigate security incidents
- 🎯 Map detections to MITRE ATT&CK techniques
- 🧪 Validate detections using controlled test activity

---

# 🏗️ Architecture

The complete monitoring and detection flow is:

```text
                         🖥️ Windows 11 Endpoint
                                  │
                  ┌───────────────┴───────────────┐
                  │                               │
          🔐 Windows Security Logs              ⚙️ Sysmon
                  │                               │
                  └───────────────┬───────────────┘
                                  │
                                  ▼
                           🔗 Azure Arc
                                  │
                                  ▼
                    📡 Azure Monitor Agent (AMA)
                                  │
                                  ▼
                     📋 Data Collection Rule
                                  │
                                  ▼
                      📊 Log Analytics Workspace
                                  │
                                  ▼
                         🛡️ Microsoft Sentinel
                                  │
                                  ▼
                            🔎 KQL Queries
                                  │
                                  ▼
                         🚨 Analytics Rules
                                  │
                                  ▼
                           📢 Security Alerts
                                  │
                                  ▼
                          📌 Security Incidents
                                  │
                                  ▼
                     🔍 Investigation & Analysis
                                  │
                                  ▼
                         🎯 MITRE ATT&CK Mapping
☁️ Azure Resources

The lab was implemented using the following Azure resources:

Component	Configuration
☁️ Subscription	Azure for Students
📁 Resource Group	sentinel-soc-lab
🌍 Region	Central India
📊 Log Analytics Workspace	sentinel-law
🔗 Azure Arc Machine	DESKTOP-00BENSL
📡 Monitoring Agent	Azure Monitor Agent
📋 Data Collection Rule	sentinel-windows-security
🛡️ SIEM	Microsoft Sentinel
💻 Endpoint	Windows 11 Home
1️⃣ Create the Azure Resource Group

The first step was creating a dedicated Resource Group for the SOC lab.

Resource Group
      │
      ├── Log Analytics Workspace
      ├── Microsoft Sentinel
      ├── Azure Arc resources
      └── Monitoring configuration
📌 Configuration

Resource Group:

sentinel-soc-lab

Region:

Central India

The Resource Group provides a central location for managing the Azure resources used by the project.

2️⃣ Create the Log Analytics Workspace

A Log Analytics Workspace was created to store and query security telemetry collected from the Windows endpoint.

📊 Workspace
sentinel-law

The workspace acts as the central log repository before the data is analyzed through Microsoft Sentinel.

3️⃣ Enable Microsoft Sentinel

Microsoft Sentinel was enabled on the Log Analytics Workspace.

sentinel-law
      │
      ▼
Microsoft Sentinel

Microsoft Sentinel provides the SIEM functionality required for:

🔎 Log analysis
🚨 Alert generation
📌 Incident management
🧑‍💻 Investigation
🎯 Threat detection
4️⃣ Connect Windows Endpoint Using Azure Arc

The Windows 11 machine was onboarded to Azure using Azure Arc.

💻 Endpoint
DESKTOP-00BENSL

Azure Arc allows the Windows machine to be represented and managed as an Azure resource.

✅ Validation

The Azure Arc agent was successfully connected.

Status: Connected
Agent Version: 1.67.03504.3207
Operating System: Windows 11 Home
5️⃣ Install Azure Monitor Agent

Azure Monitor Agent (AMA) was installed on the Azure Arc connected machine.

📡 Agent
AzureMonitorWindowsAgent
Configuration
Version: 1.45.0.0
Status: Succeeded
Automatic Upgrade: Enabled

AMA is responsible for collecting telemetry from the Windows endpoint and sending it according to the configured Data Collection Rule.

6️⃣ Configure Data Collection Rule

A Data Collection Rule (DCR) was created to define which Windows logs should be collected.

📋 DCR
sentinel-windows-security
Destination
sentinel-law

The DCR was configured to collect:

🔐 Windows Security Events

Windows Security events were collected for authentication and security monitoring.

Important Event IDs included:

4625 → Failed logon
⚙️ Sysmon Events

Sysmon operational events were also configured:

Microsoft-Windows-Sysmon/Operational

This allowed process creation and other endpoint telemetry to be monitored.

7️⃣ Validate Agent Connectivity

After configuring Azure Arc, AMA, and the DCR, the next step was validating that telemetry was actually reaching Azure.

The following KQL query was used:

Heartbeat
| where TimeGenerated > ago(30m)
| project TimeGenerated, Computer, Category, OSType
| order by TimeGenerated desc
✅ Result

Heartbeat events were received from:

DESKTOP-00BENSL

This confirmed that Azure Monitor Agent was communicating successfully with the Log Analytics Workspace.

8️⃣ Validate Windows Security Events

The expected SecurityEvent table did not contain the required events in this environment.

Instead of assuming that logging was broken, the generic Event table was investigated.

The following query was used:

Event
| where TimeGenerated > ago(30m)
| where EventLog == "Security"
| project TimeGenerated, Computer, EventID, RenderedDescription
| order by TimeGenerated desc
✅ Result

Windows Security events were successfully found in the Event table.

For example:

Event ID: 4798

This confirmed that Windows Security telemetry was reaching Log Analytics.

9️⃣ Validate Failed Login Events

A controlled failed-login test was performed to generate Windows Event ID 4625.

The following KQL query was used:

Event
| where TimeGenerated > ago(15m)
| where EventLog == "Security"
| where EventID == 4625
| project TimeGenerated, Computer, EventID, RenderedDescription
| order by TimeGenerated desc
🔐 Event ID 4625

Event ID 4625 represents:

An account failed to log on.

Multiple events were successfully detected.

⚠️ The wrong-password testing was stopped after validation to avoid unnecessary account lockout or excessive failed-login activity.

🔟 Install and Configure Sysmon

Sysmon was installed on the Windows endpoint using Microsoft Sysinternals.

Installation was performed from an Administrator PowerShell session.

cd .\Sysmon
.\Sysmon64.exe -accepteula -i
✅ Validation

Sysmon was verified using:

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5

Sysmon Event IDs including:

Event ID 1 → Process Creation
Event ID 5 → Process Termination

were observed.

1️⃣1️⃣ Validate Sysmon Events in Sentinel

The Sysmon events were then searched in Log Analytics.

Event
| where TimeGenerated > ago(1h)
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 1
| project TimeGenerated, Computer, EventID, RenderedDescription
| order by TimeGenerated desc
✅ Result

Sysmon Event ID 1 process creation events were successfully received.

This confirmed the complete telemetry path:

Windows
   ↓
Sysmon
   ↓
AMA
   ↓
DCR
   ↓
Log Analytics
   ↓
Microsoft Sentinel
🚨 Detection Engineering

Two main security detections were implemented.

🔐 Detection 1
Multiple Failed Windows Logins

        +

⚡ Detection 2
Suspicious PowerShell / Command Shell Execution
🔐 Detection 1 — Multiple Failed Windows Logins
🎯 Objective

Detect repeated failed Windows authentication attempts that may indicate brute-force activity.

KQL
Event
| where TimeGenerated > ago(10m)
| where EventLog == "Security"
| where EventID == 4625
| summarize FailedAttempts = count() by Computer
| where FailedAttempts >= 5
⚙️ Analytics Rule Configuration
Setting	Value
📌 Rule Name	SOC - Multiple Failed Windows Logins
🚨 Severity	Medium
🎯 Tactic	Credential Access
🎯 Technique	T1110 – Brute Force
⏱️ Query Period	10 minutes
🔄 Frequency	5 minutes
🔢 Threshold	5 or more failed attempts
📌 Incident Creation	Enabled
🧪 Failed Login Detection Validation

A temporary test account was created:

SentinelTest

Controlled failed authentication attempts were generated.

The following command was used:

net use \\127.0.0.1\IPC$ /user:.\SentinelTest WrongPassword123!

The command produced:

System error 1326

A corresponding Windows Security Event ID 4625 was generated.

The events were then confirmed in Log Analytics.

✅ Detection Result
Windows Event 4625
        ↓
Log Analytics
        ↓
KQL Detection
        ↓
Analytics Rule
        ↓
🚨 Security Alert
        ↓
📌 Security Incident #4
⚡ Detection 2 — Suspicious PowerShell Execution
🎯 Objective

Detect PowerShell process execution using Sysmon process creation events.

An initial query searched for several command-line tools:

Event
| where TimeGenerated > ago(1h)
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 1
| where RenderedDescription has_any (
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe"
)
| project TimeGenerated, Computer, EventID, RenderedDescription
| order by TimeGenerated desc
🛠️ Detection Query Refinement

The initial query produced a false positive.

For example, a conhost.exe event matched because powershell.exe appeared in the ParentImage information.

❌ Problem

The query was detecting the presence of the string rather than confirming that PowerShell itself was the executed process.

✅ Solution

The actual process Image field was extracted from RenderedDescription.

Event
| where TimeGenerated > ago(6h)
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 1
| extend Image = extract(@"Image:\s+([^\s]+)", 1, RenderedDescription)
| where Image endswith "powershell.exe"
| project TimeGenerated, Computer, Image, RenderedDescription
| order by TimeGenerated desc

This provided a more precise PowerShell detection.

🧪 PowerShell Detection Validation

Controlled PowerShell commands were executed:

powershell.exe -NoProfile -Command "Write-Output 'Sentinel Sysmon test'"

and:

powershell.exe -NoProfile -Command "Write-Output 'Sentinel SOC detection test'"

Sysmon recorded the process creation events.

The events were then detected through KQL.

🎯 MITRE ATT&CK
T1059
Command and Scripting Interpreter

T1059.001
PowerShell
🚨 Analytics Rules

The project contains two Sentinel Analytics Rules.

🔐 Rule 1
SOC - Multiple Failed Windows Logins

Purpose:

Detect repeated Windows authentication failures.

MITRE:

Credential Access
└── T1110 Brute Force
⚡ Rule 2
SOC - Suspicious PowerShell or Command Shell Execution

Purpose:

Detect suspicious command or PowerShell process execution.

MITRE:

Execution
└── T1059 Command and Scripting Interpreter
📢 Security Alerts

When the Analytics Rules matched the configured conditions, Microsoft Sentinel generated security alerts.

The alerts were validated through the Sentinel backend and Log Analytics.

Example query:

SecurityAlert
| where TimeGenerated > ago(1h)
| project
    TimeGenerated,
    AlertName,
    AlertSeverity,
    ProviderName
| order by TimeGenerated desc
✅ Result

Alerts were successfully generated for the configured detections.

📌 Security Incidents

Alerts were correlated into Microsoft Sentinel security incidents.

Incidents were checked using:

SecurityIncident
| where TimeGenerated > ago(24h)
| project
    TimeGenerated,
    IncidentNumber,
    Title,
    Status,
    Severity
| order by TimeGenerated desc

This confirmed that the detection-to-incident workflow was functioning.

🔎 Incident #4 — Investigation

The validated failed-login detection generated:

Incident Number: 4
Title: SOC - Multiple Failed Windows Logins
Severity: Medium
Status: New
Host: DESKTOP-00BENSL
🧪 Investigation

The incident was investigated using the underlying Event ID 4625 records.

The events were aggregated to confirm that the configured threshold had been satisfied.

🧑‍💻 Analyst Assessment
Detection:        ✅ Triggered
Threshold:        ✅ Satisfied
Events:           ✅ Correlated
Host:             DESKTOP-00BENSL
Activity:         🧪 Controlled test
Confirmed Attack: ❌ No

The activity was intentionally generated for detection validation and should not be interpreted as a confirmed malicious attack.

🎯 MITRE ATT&CK Mapping

The implemented detections were mapped to MITRE ATT&CK techniques.

Detection	Tactic	Technique
🔐 Multiple Failed Logins	Credential Access	T1110 – Brute Force
⚡ PowerShell Execution	Execution	T1059 – Command and Scripting Interpreter
⚡ PowerShell	Execution	T1059.001 – PowerShell

This mapping helps analysts understand the potential attack behavior represented by each detection.

🛠️ Issues Faced & Solutions
1️⃣ SecurityEvent Table Did Not Show Events
❌ Problem

The expected SecurityEvent table did not contain the required Windows Security events.

🔍 Investigation

The generic Event table was checked.

✅ Solution

Security events were found using:

Event
| where EventLog == "Security"

The project continued using the table that actually contained the collected telemetry.

2️⃣ Initial PowerShell Query Produced False Positives
❌ Problem

The initial query matched conhost.exe because powershell.exe appeared in parent process information.

🔍 Cause

The query searched the entire RenderedDescription.

✅ Solution

The actual Image field was extracted and checked specifically for:

powershell.exe

This improved detection precision.

3️⃣ Failed Login Analytics Rule Timing
❌ Problem

The initial failed-login detection used a short five-minute query window, which could cause timing issues between event ingestion and rule execution.

✅ Solution

The detection was adjusted to:

Lookback: 10 minutes
Frequency: 5 minutes

The KQL query was also changed to:

ago(10m)

This provided a more reliable detection window.

4️⃣ Microsoft Sentinel / Defender Portal Redirect Issue
❌ Problem

The Microsoft Defender portal Analytics interface repeatedly redirected back to the SIEM Workspaces page instead of opening the Analytics Rules interface.

The workspace was already connected and configured.

🔍 Investigation

The Sentinel backend continued to function correctly even though the portal interface was problematic.

✅ Solution

The Analytics Rules were created and verified through the Sentinel backend/API.

The following were successfully confirmed:

✅ Analytics Rules existed
✅ Rules were enabled
✅ Correct severity was configured
✅ MITRE tactics/techniques were configured
✅ Security alerts were generated
✅ Security incidents were generated
✅ Incidents could be investigated through Log Analytics

Therefore, the portal UI issue did not prevent completion of the SOC workflow.

🔎 Investigation Queries

The repository contains reusable KQL investigation queries.

🔐 Recent Failed Logins
Event
| where TimeGenerated > ago(30m)
| where EventLog == "Security"
| where EventID == 4625
| project TimeGenerated, Computer, EventID, RenderedDescription
| order by TimeGenerated desc
📊 Failed Login Count
Event
| where TimeGenerated > ago(30m)
| where EventLog == "Security"
| where EventID == 4625
| summarize FailedAttempts = count() by Computer
| order by FailedAttempts desc
⚙️ Sysmon Process Creation
Event
| where TimeGenerated > ago(30m)
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 1
| project TimeGenerated, Computer, EventID, RenderedDescription
| order by TimeGenerated desc
⚡ PowerShell Process Investigation
Event
| where TimeGenerated > ago(30m)
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 1
| extend Image = extract(@"Image:\s+([^\s]+)", 1, RenderedDescription)
| where Image endswith "powershell.exe"
| project TimeGenerated, Computer, Image, RenderedDescription
| order by TimeGenerated desc
📂 Repository Structure
microsoft-sentinel-soc-lab/
│
├── 📁 architecture/
│   └── sentinel-soc-architecture.md
│
├── 📁 kql/
│   ├── failed-login-detection.kql
│   ├── powershell-detection.kql
│   └── investigation-queries.kql
│
├── 📁 detections/
│   ├── multiple-failed-logins.md
│   └── suspicious-powershell.md
│
├── 📁 investigations/
│   └── incident-004.md
│
├── 📁 screenshots/
│   ├── 01-azure-student-subscription.png
│   ├── 02-resource-group.png
│   ├── 03-log-analytics-workspace.png
│   ├── 04-microsoft-sentinel.png
│   ├── 05-azure-arc-onboarding-success.png
│   ├── 06-azure-arc-machine-connected.png
│   ├── 07-ama-extension-success.png
│   ├── 08-data-collection-rule.png
│   ├── 09-ama-heartbeat.png
│   ├── 10-windows-security-events.png
│   ├── 11-event-4625.png
│   ├── 12-failed-login-kql.png
│   ├── 13-sysmon-installed.png
│   ├── 14-sysmon-event-1.png
│   ├── 15-sysmon-kql.png
│   ├── 16-failed-login-analytics-rule.png
│   ├── 17-powershell-analytics-rule.png
│   ├── 18-security-alert.png
│   ├── 19-security-incident.png
│   ├── 20-incident-004-investigation.png
│   └── 21-mitre-attack-mapping.png
│
└── 📄 README.md
📜 KQL Files

All KQL queries are stored inside the:

kql/

directory.

🔐 failed-login-detection.kql

Contains the detection logic for repeated Windows Event ID 4625 failures.

⚡ powershell-detection.kql

Contains the refined Sysmon PowerShell process detection.

🔎 investigation-queries.kql

Contains queries used during incident investigation and validation.

These files are KQL source files, not PowerShell or CMD scripts.

They can be copied into:

Azure Portal
    ↓
Log Analytics Workspace
    ↓
sentinel-law
    ↓
Logs
    ↓
Paste KQL
    ↓
Run

The detection queries can also be used as the query logic for Microsoft Sentinel Analytics Rules.

📸 Evidence

The screenshots/ directory contains evidence collected during the implementation.

The evidence demonstrates:

☁️ Azure resource configuration
🔗 Azure Arc onboarding
📡 AMA installation
📋 DCR configuration
💓 Agent heartbeat
🔐 Windows Security events
⚙️ Sysmon installation
🔎 KQL queries
🚨 Analytics Rules
📢 Security Alerts
📌 Security Incidents
🔍 Incident investigation
🎯 MITRE ATT&CK mapping
🔐 Security Considerations

The repository should not contain sensitive information such as:

❌ Passwords
❌ API keys
❌ Access tokens
❌ Client secrets
❌ Authentication credentials
❌ Azure-generated onboarding tokens

Azure-generated onboarding scripts containing authentication information should not be committed to a public repository.

Screenshots should also be reviewed before publishing to ensure sensitive identifiers or credentials are not exposed.

🧪 End-to-End Validation

The final SOC workflow was validated as follows:

🖥️ Windows Endpoint
        │
        ▼
🔐 Security Logs + ⚙️ Sysmon
        │
        ▼
🔗 Azure Arc
        │
        ▼
📡 Azure Monitor Agent
        │
        ▼
📋 Data Collection Rule
        │
        ▼
📊 Log Analytics
        │
        ▼
🛡️ Microsoft Sentinel
        │
        ▼
🔎 KQL Detection
        │
        ▼
🚨 Analytics Rule
        │
        ▼
📢 Security Alert
        │
        ▼
📌 Security Incident
        │
        ▼
🔍 Investigation
        │
        ▼
🎯 MITRE ATT&CK
✅ Final Validation
Component	Status
🖥️ Windows Endpoint	✅
🔗 Azure Arc	✅
📡 Azure Monitor Agent	✅
📋 Data Collection Rule	✅
📊 Log Analytics	✅
🛡️ Microsoft Sentinel	✅
🔐 Windows Security Events	✅
⚙️ Sysmon Events	✅
🔎 KQL Detection	✅
🚨 Analytics Rules	✅
📢 Security Alerts	✅
📌 Security Incidents	✅
🔍 Incident Investigation	✅
🎯 MITRE Mapping	✅
🏁 Conclusion

This project demonstrates a complete Windows-focused SOC monitoring and detection workflow using Microsoft Sentinel.

The lab successfully covered:

📥 Telemetry Collection
        ↓
📊 Centralized Logging
        ↓
🔎 Detection Engineering
        ↓
🚨 Alert Generation
        ↓
📌 Incident Creation
        ↓
🔍 Investigation
        ↓
🎯 MITRE ATT&CK Mapping

The project also demonstrates practical troubleshooting, including identifying the correct Log Analytics table, refining detection logic to reduce false positives, adjusting analytics-rule timing, and working around a Sentinel portal UI issue while validating the backend functionality.

🛡️ Project Focus

Windows Security Monitoring • Microsoft Sentinel • Azure Arc • AMA • Sysmon • KQL • Detection Engineering • Incident Response • MITRE ATT&CK


### 👍 One important thing

- 🏗️ = architecture
- ☁️ = Azure
- 🔐 = authentication/security
- ⚙️ = configuration/Sysmon
- 🔎 = investigation
- 🚨 = detection/alert
- 📌 = incident
- 🎯 = MITRE
- 🛠️ = troubleshooting
- ✅ = validated
