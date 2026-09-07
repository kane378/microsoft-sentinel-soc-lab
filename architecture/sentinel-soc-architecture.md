\# Microsoft Sentinel SOC Lab Architecture



\## Architecture Overview



```mermaid

flowchart TD

&#x20;   A\[Windows 11 Endpoint] --> B\[Windows Security Events]

&#x20;   A --> C\[Sysmon]

&#x20;   

&#x20;   B --> D\[Azure Arc]

&#x20;   C --> D

&#x20;   

&#x20;   D --> E\[Azure Monitor Agent - AMA]

&#x20;   E --> F\[Data Collection Rule]

&#x20;   F --> G\[Log Analytics Workspace]

&#x20;   G --> H\[Microsoft Sentinel]

&#x20;   

&#x20;   H --> I\[KQL Detection]

&#x20;   I --> J\[Analytics Rules]

&#x20;   J --> K\[Security Alerts]

&#x20;   K --> L\[Security Incidents]

&#x20;   

&#x20;   L --> M\[SOC Investigation]

&#x20;   M --> N\[MITRE ATT\&CK Mapping]

