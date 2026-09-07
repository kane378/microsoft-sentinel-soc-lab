Microsoft Sentinel SOC Lab

End-to-End Windows SOC Monitoring, Detection Engineering & Incident Investigation

A hands-on Security Operations Center (SOC) lab built with
Microsoft Sentinel, Azure Arc, Azure Monitor Agent (AMA), Azure Log
Analytics, Windows Security Events, Sysmon, and Kusto Query Language
(KQL).

This project demonstrates a complete security monitoring workflow:

Endpoint telemetry → Collection → Centralized logging → Detection
engineering → Alert generation → Incident creation → Investigation →
MITRE ATT&CK mapping

Lab status: End-to-end detection pipeline validated
Environment: Windows 11 + Microsoft Azure
Primary SIEM: Microsoft Sentinel
Query language: KQL

1. Project Overview

The goal of this project was to build and validate a practical SOC
monitoring environment around a Windows 11 endpoint.

The lab covers:

Windows Security Event Log collection

Sysmon endpoint telemetry

Azure Arc endpoint onboarding

Azure Monitor Agent (AMA)

Data Collection Rules (DCR)

Centralized logging in Azure Log Analytics

KQL-based security investigation

Microsoft Sentinel Analytics Rules

Security alert generation

Automatic incident creation

Detection refinement and false-positive analysis

MITRE ATT&CK mapping

SOC investigation and response methodology

All security activity used for validation was intentionally generated in
a controlled lab environment.

2. SOC Architecture

flowchart LR
    A[Windows 11 Endpoint] --> B[Windows Security Events]
    A --> C[Sysmon]
    B --> D[Azure Arc]
    C --> D
    D --> E[Azure Monitor Agent]
    E --> F[Data Collection Rule]
    F --> G[Log Analytics Workspace]
    G --> H[Microsoft Sentinel]
    H --> I[KQL Detection Queries]
    I --> J[Analytics Rules]
    J --> K[Security Alerts]
    K --> L[Security Incidents]
    L --> M[SOC Investigation]
    M --> N[MITRE ATT&CK Mapping]
    N --> O[Analyst Assessment & Response]

End-to-End Flow

Windows 11 Endpoint
        ↓
Windows Security Events + Sysmon
        ↓
Azure Arc
        ↓
Azure Monitor Agent (AMA)
        ↓
Data Collection Rule (DCR)
        ↓
Azure Log Analytics
        ↓
Microsoft Sentinel
        ↓
KQL
        ↓
Analytics Rules
        ↓
Security Alerts
        ↓
Security Incidents
        ↓
Investigation
        ↓
MITRE ATT&CK
        ↓
Analyst Assessment & Response

3. Lab Environment

Component                 Configuration

Endpoint                  Windows 11 Home
Endpoint Management       Azure Arc
Monitoring Agent          Azure Monitor Agent (AMA)
Collection                Data Collection Rule (DCR)
SIEM                      Microsoft Sentinel
Log Platform              Azure Log Analytics
Query Language            Kusto Query Language (KQL)
Endpoint Telemetry        Sysmon
Detection Framework       MITRE ATT&CK
Azure Region              Central India
Resource Group            sentinel-soc-lab
Log Analytics Workspace   sentinel-law
DCR                       sentinel-windows-security
Endpoint                  DESKTOP-00BENSL

4. Azure Resource Setup

The lab was deployed using an Azure for Students subscription.

Core resources:

Subscription
└── Resource Group: sentinel-soc-lab
    ├── Log Analytics Workspace: sentinel-law
    ├── Microsoft Sentinel
    └── Azure Arc connected endpoint
        └── DESKTOP-00BENSL

Microsoft Sentinel was connected to the Log Analytics workspace and used
as the SIEM and detection layer.

5. Endpoint Onboarding with Azure Arc

The Windows 11 endpoint was onboarded to Azure using Azure Arc.

Azure Arc allows a non-Azure Windows machine to be represented and
managed as an Azure resource.

Endpoint

Computer: DESKTOP-00BENSL
OS: Windows 11 Home
Azure Arc: Connected

The successful Arc connection provided the foundation for installing and
managing the Azure Monitor Agent.

6. Azure Monitor Agent

The Azure Monitor Agent (AMA) was installed on the Windows endpoint.

AMA is responsible for collecting configured telemetry and forwarding it
to Azure according to the Data Collection Rule.

The AMA extension was successfully installed and reported a
healthy/succeeded state.

7. Data Collection Rule

A Data Collection Rule named:

sentinel-windows-security

was configured to collect Windows Event Logs and send them to:

sentinel-law

Windows Security Events

Security events were collected from the Windows Security log, including
authentication-related events.

The primary authentication event used in this project was:

Event ID 4625
An account failed to log on

Sysmon Events

The DCR was later updated to collect the Sysmon operational channel:

Microsoft-Windows-Sysmon/Operational

This enabled endpoint process telemetry, including:

Event ID 1 - Process Create
Event ID 5 - Process Terminated

8. Telemetry Validation

Before creating detections, every stage of the telemetry pipeline was
validated.

AMA Heartbeat

The following KQL query was used to confirm that the endpoint and AMA
were communicating with Azure:

Heartbeat
| where TimeGenerated > ago(30m)
| project TimeGenerated, Computer, Category, OSType
| order by TimeGenerated desc

Heartbeat records confirmed that:

The endpoint was connected.

AMA was running.

Telemetry was reaching Log Analytics.

Windows Security Log Validation

The expected SecurityEvent table did not return the required results
in this environment.

Instead of assuming that ingestion had failed, the generic Event table
was investigated:

Event
| where TimeGenerated > ago(30m)
| where EventLog == "Security"
| project TimeGenerated, Computer, EventID, RenderedDescription
| order by TimeGenerated desc

This confirmed that Windows Security events were successfully arriving
in Log Analytics.

This was an important troubleshooting step: an empty expected table
does not necessarily mean that telemetry collection is broken.

9. Event ID 4625 --- Failed Authentication Detection

Windows Event ID 4625 represents a failed account logon.

A controlled authentication test was performed using a temporary local
test account.

The resulting telemetry was verified through the complete pipeline:

Windows Security Log
        ↓
Azure Monitor Agent
        ↓
Log Analytics
        ↓
KQL

Multiple Event ID 4625 records were observed in Log Analytics and were
then used to build the Sentinel detection.

10. Sysmon Integration

Sysmon was installed on the Windows endpoint to provide richer
process-level visibility.

Installation was verified using:

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5

The endpoint generated Sysmon telemetry including:

Event ID 1  → Process Create
Event ID 5  → Process Terminated

The DCR was then configured to collect:

Microsoft-Windows-Sysmon/Operational

Sysmon Event ID 1 records were successfully observed in Log Analytics.

11. Detection Engineering

Two primary Microsoft Sentinel Analytics Rules were implemented and
validated.

Detection 1 --- Multiple Failed Windows Logins

Rule

SOC - Multiple Failed Windows Logins

Objective

Detect repeated failed authentication attempts on a Windows endpoint
that could indicate password guessing, brute-force activity, or another
authentication-related issue.

Configuration

Property            Value

Data Source         Windows Security Event Log
Event               4625
Severity            Medium
Tactic              Credential Access
Technique           T1110 - Brute Force
Detection Window    10 minutes
Threshold           5 or more failures
Frequency           5 minutes
Incident Creation   Enabled

Detection Query

Event
| where TimeGenerated > ago(10m)
| where EventLog == "Security"
| where EventID == 4625
| summarize
    FailedAttempts = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Computer
| where FailedAttempts >= 5
| project FirstSeen, LastSeen, Computer, FailedAttempts
| order by FailedAttempts desc

Detection Logic

The rule looks for:

5 or more Event ID 4625 events
within a 10-minute investigation window

When the threshold is reached, Sentinel generates a security alert and
creates an incident.

Detection 2 --- Suspicious PowerShell Execution

Rule

SOC - Suspicious PowerShell or Command Shell Execution

Objective

Detect PowerShell execution using Sysmon Process Creation telemetry.

PowerShell is a legitimate administrative tool, but it is also
frequently used by attackers for execution and post-compromise activity.

Configuration

Property            Value

Data Source         Sysmon Operational Log
Event               Event ID 1 - Process Create
Severity            Medium
Tactic              Execution
Technique           T1059 - Command and Scripting Interpreter
Sub-technique       T1059.001 - PowerShell
Incident Creation   Enabled

Detection Query

Event
| where TimeGenerated > ago(6h)
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 1
| extend Image = extract(@"Image:\s+([^\s]+)", 1, RenderedDescription)
| where Image endswith "powershell.exe"
| project TimeGenerated, Computer, Image, RenderedDescription
| order by TimeGenerated desc

12. Detection Refinement & False-Positive Analysis

The initial PowerShell detection searched the complete Sysmon event
description:

RenderedDescription has_any (
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe"
)

During testing, this approach was found to be too broad.

For example, a conhost.exe process could contain powershell.exe in
the ParentImage field. Searching the complete description could
therefore identify the child process as PowerShell even when the actual
process image was different.

Refined Detection

The detection was changed to extract the actual Image field:

| extend Image = extract(@"Image:\s+([^\s]+)", 1, RenderedDescription)
| where Image endswith "powershell.exe"

This refinement makes the detection more precise because it evaluates
the actual process executable rather than simply searching for the
string powershell.exe anywhere in the event.

SOC Lesson

Detection rules should be tested against real telemetry and refined
when field context creates false positives.

This is an important part of detection engineering: high-quality
detections are not simply written once; they are validated,
investigated, and improved.

13. Analytics Rule → Alert → Incident

Both detections were tested using controlled security activity.

The complete Sentinel pipeline was validated:

Endpoint Activity
       ↓
Windows / Sysmon Telemetry
       ↓
Azure Monitor Agent
       ↓
Log Analytics
       ↓
KQL Detection
       ↓
Sentinel Analytics Rule
       ↓
Security Alert
       ↓
Security Incident
       ↓
SOC Investigation

PowerShell Detection

Controlled PowerShell execution generated Sysmon Event ID 1 telemetry.

The corresponding Analytics Rule successfully generated Sentinel
security alerts and incidents.

Failed Login Detection

Controlled failed authentication activity generated multiple Event ID
4625 events.

After the threshold was reached, the Sentinel Analytics Rule generated
security alerts and an associated incident.

This validated that the project was not limited to log collection: the
telemetry was successfully converted into actionable SOC detections.

14. Incident Investigation

A generated failed-login incident was investigated using KQL.

Incident

Incident Number: 4
Title: SOC - Multiple Failed Windows Logins
Severity: Medium
Status: New
Affected Host: DESKTOP-00BENSL

Investigation Query

Event
| where TimeGenerated > ago(30m)
| where EventLog == "Security"
| where EventID == 4625
| project
    TimeGenerated,
    Computer,
    EventID,
    RenderedDescription
| order by TimeGenerated desc

Aggregation Query

Event
| where TimeGenerated > ago(30m)
| where EventLog == "Security"
| where EventID == 4625
| summarize
    FailedAttempts = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Computer
| order by FailedAttempts desc

The investigation confirmed repeated failed authentication events on:

DESKTOP-00BENSL

The event count satisfied the configured detection threshold.

15. Analyst Assessment

The failed-login activity was intentionally generated as part of the SOC
validation process.

A temporary local test account was used to create controlled
authentication failures.

Therefore, the final analyst assessment was:

Assessment            Result

Detection             Validated
Activity              Controlled Test
Detection Threshold   Satisfied
Confirmed Attack      No

The incident demonstrates that the detection mechanism can identify
repeated authentication failures. However, the controlled test itself
should not be classified as a real brute-force attack.

In a production SOC, the analyst would need additional evidence before
determining malicious intent.

16. MITRE ATT&CK Mapping

The implemented detections were mapped to relevant MITRE ATT&CK
techniques.

Detection               Tactic                  MITRE ATT&CK

Multiple Failed Windows Credential Access       T1110 - Brute Force
Logins

Suspicious PowerShell   Execution               T1059 - Command and
Scripting Interpreter

PowerShell              Execution               T1059.001 - PowerShell

MITRE ATT&CK mapping provides a standardized way to describe adversary
behaviors represented by security detections.

Important: A technique mapping describes the behavior represented
by the detection; it does not by itself prove that an actual attack
occurred.

17. SOC Investigation Methodology

When an alert or incident is generated, an analyst should follow a
structured investigation process.

Step 1 --- Identify the Host

Determine which endpoint generated the activity.

Step 2 --- Identify the Account or Process

For authentication detections:

Identify the targeted account.

Review authentication details.

Determine whether the account is expected.

For process detections:

Identify the executable.

Review the process path.

Review the user context.

Examine the parent process.

Step 3 --- Establish a Timeline

Determine:

First occurrence

Last occurrence

Number of events

Related activity before the alert

Related activity after the alert

Step 4 --- Review Related Events

Search for:

Successful logons

Additional failed logons

Process creation

PowerShell activity

Related endpoint activity

Other suspicious behavior

Step 5 --- Determine Intent

Classify the activity as:

Expected
Suspicious
Malicious
Controlled Testing

Step 6 --- Map to MITRE ATT&CK

Map confirmed or relevant adversary behavior to the appropriate ATT&CK
technique.

Step 7 --- Respond

Depending on the investigation, response actions may include:

Credential protection

Account investigation

Endpoint isolation

Process termination

Additional threat hunting

Escalation to higher SOC tiers

Automated response playbooks

18. KQL Query Repository

The kql/ directory contains the queries used for detection and
investigation.

kql/
├── failed-login-detection.kql
├── powershell-detection.kql
└── investigation-queries.kql

These queries can be imported, modified, or extended for future
Microsoft Sentinel investigations.

19. Repository Structure

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
    └── project evidence

20. Project Evidence

The screenshots/ directory contains implementation and validation
evidence collected during the lab.

Evidence includes:

Azure subscription

Resource Group

Log Analytics Workspace

Microsoft Sentinel

Azure Arc

Azure Monitor Agent

Data Collection Rule

Sysmon installation

Windows Security Events

Event ID 4625

Sysmon Event ID 1

KQL queries

Analytics Rules

Security Alerts

Security Incidents

Investigation results

MITRE ATT&CK mapping

The screenshots demonstrate that the environment was actually configured
and tested rather than being a documentation-only project.

Before publishing the repository publicly, verify that screenshots do
not contain passwords, tokens, API keys, personal information, or
other secrets.

21. Microsoft Defender Portal Limitation

During the lab, some Microsoft Sentinel experiences in the Microsoft
Defender portal intermittently redirected back to the SIEM
Workspaces/settings area.

The portal displayed a message similar to:

This page was moved to the Microsoft Defender portal.

The behavior was inconsistent: some Sentinel pages were accessible while
Analytics/Incidents experiences could intermittently redirect.

Importantly, this did not prevent validation of the underlying
Sentinel backend.

The following components were independently validated:

Telemetry Ingestion
        ↓
Log Analytics Queries
        ↓
Analytics Rules
        ↓
Security Alerts
        ↓
Security Incidents

The Analytics Rules were created and verified through the Sentinel
backend, and alerts/incidents were confirmed using Log Analytics
queries.

Therefore, the portal UI limitation was treated as an
environment/platform issue rather than a failure of the SOC detection
pipeline.

22. Security Considerations

This repository documents a controlled cybersecurity laboratory.

Testing Scope

Testing was performed against a controlled Windows endpoint
owned/managed for the lab.

Authentication Testing

A temporary local test account was used to generate failed
authentication events.

Credentials

Do not commit:

Passwords

API keys

Access tokens

Azure credentials

Connection strings

Private keys

Other secrets

Controlled Activity

The PowerShell and authentication activity used during validation was
intentionally generated for detection testing.

It should not be interpreted as evidence of an actual compromise.

23. Lessons Learned

This project provided practical experience with:

Windows security telemetry

Endpoint monitoring

Azure Arc onboarding

Azure Monitor Agent

Data Collection Rules

Azure Log Analytics

Microsoft Sentinel

KQL detection engineering

Windows Event ID analysis

Sysmon telemetry

Analytics Rules

Security alerts

Security incidents

False-positive investigation

MITRE ATT&CK mapping

SOC investigation methodology

Troubleshooting cloud-based security monitoring pipelines

Key Lesson

A SOC pipeline should be validated stage by stage.

When a query returns no results, an analyst should not immediately
assume that the telemetry source is broken.

In this project, investigating the available Event table instead of
stopping at the empty SecurityEvent table revealed that the required
Windows Security telemetry was actually being ingested successfully.

24. Future Improvements

The current implementation can be extended with:

Detection Engineering

Additional Windows Security Event detections

More Sysmon event coverage

Advanced PowerShell detections

Suspicious parent-child process analysis

Credential theft detections

Lateral movement detections

Persistence detections

Threat Intelligence

Threat intelligence enrichment

IOC correlation

Automated indicator lookup

External threat intelligence feeds

Investigation & Automation

Automated MITRE ATT&CK mapping

Automated incident summaries

Automated remediation recommendations

Threat hunting queries

SOAR response playbooks

Automated alert prioritization

Telemetry Expansion

Network telemetry

DNS monitoring

Firewall logs

Authentication telemetry from additional systems

Cloud security logs

25. Final Outcome

The project successfully demonstrated an end-to-end Windows SOC
monitoring and detection workflow:

Windows 11 Endpoint
        ↓
Azure Arc
        ↓
Azure Monitor Agent
        ↓
Data Collection Rule
        ↓
Azure Log Analytics
        ↓
Microsoft Sentinel
        ↓
KQL
        ↓
Analytics Rules
        ↓
Security Alerts
        ↓
Security Incidents
        ↓
Investigation
        ↓
MITRE ATT&CK
        ↓
Analyst Assessment

Key Results

Windows endpoint successfully onboarded with Azure Arc.

Azure Monitor Agent successfully deployed.

Windows Security telemetry successfully collected.

Sysmon successfully integrated.

Event ID 4625 successfully detected.

Sysmon Event ID 1 successfully detected.

KQL detection queries developed and tested.

PowerShell detection logic refined to reduce false positives.

Multiple Sentinel Analytics Rules created.

Security alerts successfully generated.

Security incidents successfully generated.

Incident investigation performed using KQL.

MITRE ATT&CK techniques mapped.

End-to-end SOC detection pipeline validated.

26. Disclaimer

This project is an educational cybersecurity laboratory created for
defensive security monitoring, detection engineering, and SOC
investigation practice.

All testing described in this repository was performed in a controlled
environment. The project is intended for authorized systems and
educational use only.

Project Summary

Microsoft Sentinel SOC Lab demonstrates how a security analyst can
move from raw endpoint telemetry to an actionable security incident
using Microsoft Azure and Microsoft Sentinel.

The most important outcome is not simply that logs were collected, but
that the project validated the complete SOC workflow:

Collect → Detect → Alert → Investigate → Assess → Map → Respond
