\# MiniSOC — Technical Architecture



\## 1. Overview



MiniSOC is a Windows-focused security monitoring platform developed with Python. Its architecture collects endpoint telemetry, processes security events through custom detection logic, stores generated alerts in SQLite, and presents security activity through a Streamlit dashboard.



The platform also includes an incident management component for organizing investigations and tracking incident response activities.



\## 2. Architecture Components



\### 2.1 Windows Endpoint



The Windows endpoint is the primary source of security telemetry.



Two event sources are monitored:



\- \*\*Sysmon:\*\* Provides process creation telemetry, including executable paths, command-line arguments, and parent process information.

\- \*\*Windows Security Event Logs:\*\* Provides authentication activity, including successful logons (Event ID 4624) and failed logons (Event ID 4625).



\### 2.2 Event Collection Layer



The collection layer retrieves endpoint events using PowerShell and Python subprocess execution.



| Module | Responsibility |

|---|---|

| `event\_collector.py` | Collects Sysmon process events. |

| `security\_collector.py` | Collects Windows Security log events. |

| `monitor.py` | Coordinates collection, processing, and monitoring cycles. |



The collectors support baseline and incremental collection modes. Incremental collection uses Windows event record IDs to identify events newer than the current in-memory cursor.



\### 2.3 Detection Engineering Layer



Collected events are passed to the relevant detection modules.



| Module | Responsibility |

|---|---|

| `detection\_engine.py` | Detects suspicious process execution patterns. |

| `login\_detector.py` | Detects brute-force and password-spraying activity. |

| `successful\_login\_detector.py` | Detects suspicious successful login scenarios and correlates successful logins with preceding failed attempts. |



The detection logic evaluates event properties and generates structured alerts when defined conditions are met.



\### 2.4 Alert Storage Layer



`alert\_store.py` manages SQLite database initialization and alert persistence.



The database stores security alert records, including detection information and severity classification.



SQLite provides local persistence without requiring a separate database server.



\### 2.5 Dashboard Layer



`dashboard.py` implements the Streamlit user interface.



It provides:



\- Alert metrics and severity summaries.

\- Detection rule statistics.

\- Time-based filtering.

\- Alert search and investigation.

\- Security activity visualization.

\- CSV export.

\- Incident response functionality.



Pandas supports data handling and presentation within the dashboard.



\### 2.6 Incident Management Layer



`incident\_manager.py` implements incident case management using SQLite.



The incident response data model includes:



| Table | Purpose |

|---|---|

| `incidents` | Stores incident records and lifecycle status. |

| `incident\_alerts` | Links alerts to incidents. |

| `incident\_notes` | Stores investigation notes. |

| `incident\_evidence` | Stores evidence descriptions and associated metadata. |



Supported incident statuses are:



`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, and `CLOSED`.



\## 3. Event Processing Workflow



1\. Windows generates endpoint and authentication telemetry.

2\. The collectors retrieve relevant Sysmon and Security events.

3\. The monitoring engine coordinates event processing.

4\. Process events are evaluated by the process detection engine.

5\. Authentication events are evaluated by the login detection modules.

6\. Detection matches are converted into structured alerts.

7\. Alerts are stored in SQLite.

8\. The Streamlit dashboard retrieves and displays alert information.

9\. Analysts can create incidents, link alerts, record notes, and register evidence metadata.



\## 4. Architecture Diagram



```mermaid

flowchart TD

&#x20;   A\[Windows Endpoint] --> B\[Sysmon Event Log]

&#x20;   A --> C\[Windows Security Event Log]



&#x20;   B --> D\[event\_collector.py]

&#x20;   C --> E\[security\_collector.py]



&#x20;   D --> F\[monitor.py]

&#x20;   E --> F



&#x20;   F --> G\[detection\_engine.py]

&#x20;   F --> H\[login\_detector.py]

&#x20;   F --> I\[successful\_login\_detector.py]



&#x20;   G --> J\[alert\_store.py]

&#x20;   H --> J

&#x20;   I --> J



&#x20;   J --> K\[(SQLite Database)]



&#x20;   K --> L\[dashboard.py]

&#x20;   K --> M\[incident\_manager.py]

</flowchart>

```



\## 5. Monitoring and Collection Design



MiniSOC uses event record IDs to support incremental collection.



At initialization, the monitoring engine establishes a baseline from recent events and sets collection cursors. During subsequent monitoring cycles, it retrieves events newer than the stored in-memory cursors.



The monitoring loop uses a five-second polling interval.



The current implementation maintains cursors in memory. They are not persisted across application restarts.



\## 6. Data Storage



SQLite is used for local storage of alerts and incident-response records.



The database is initialized locally when the monitoring application starts. Database files are excluded from the public Git repository to avoid publishing endpoint telemetry or investigation records.



\## 7. Current Architecture Limitations



\- The current implementation is designed primarily for a single Windows endpoint.

\- Event-processing cursors are not persistent across restarts.

\- Startup collection uses bounded baseline batches.

\- Evidence registration stores metadata and file paths but does not automatically hash or preserve evidence files.

\- Some detection scenarios have been validated using synthetic events rather than real attack telemetry.



\## 8. Future Architecture Improvements



\- Persistent event-processing cursors.

\- Multi-endpoint event collection.

\- Centralized log storage.

\- Automated evidence hashing and integrity validation.

\- Alert enrichment and MITRE ATT\&CK mapping.

\- Improved event processing resilience and recovery.



\---



\*MiniSOC Technical Architecture — Security Monitoring, Detection Engineering, and Incident Response.\*
