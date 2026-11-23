\# MiniSOC — Incident Response and Case Management



\## 1. Overview



MiniSOC includes an incident management module designed to support the investigation and tracking of security alerts.



The module enables an analyst to create incident cases, assign responsibility, associate relevant alerts, document investigation activities, register evidence metadata, and track incident status through resolution.



The implementation uses Python and SQLite.



\## 2. Incident Management Capabilities



The incident management component supports:



\- Incident creation with unique case identifiers.

\- Incident severity classification.

\- Analyst assignment.

\- Linking security alerts to incident cases.

\- Investigation note recording.

\- Evidence metadata registration.

\- Incident status updates.

\- Incident resolution documentation.

\- Incident history and investigation details.



\## 3. Incident Creation



An analyst can create an incident from the dashboard.



Each incident contains:



| Field | Description |

|---|---|

| Incident ID | Internal database identifier. |

| Case ID | Unique human-readable case reference. |

| Title | Incident name or summary. |

| Description | Initial incident details. |

| Severity | HIGH, MEDIUM, or LOW. |

| Assigned analyst | Person responsible for investigation. |

| Status | Current incident lifecycle status. |

| Created timestamp | Incident creation time. |

| Updated timestamp | Most recent update time. |

| Resolution | Final resolution description, when provided. |



Case identifiers use the format:



`MINISOC-XXXXXXXX`



The identifier includes eight uppercase hexadecimal characters.



\## 4. Incident Severity



MiniSOC supports three incident severity classifications.



| Severity | Description |

|---|---|

| HIGH | Priority investigation required. |

| MEDIUM | Suspicious activity requiring analyst review. |

| LOW | Lower-priority security incident or observation. |



Severity is assigned during incident creation and can be used to prioritize investigation work.



\## 5. Incident Lifecycle



The system supports five incident statuses.



| Status | Meaning |

|---|---|

| OPEN | Incident has been created and requires investigation. |

| INVESTIGATING | An analyst is actively investigating the incident. |

| CONTAINED | Immediate containment actions have been recorded. |

| RESOLVED | Investigation and remediation have reached resolution. |

| CLOSED | Incident has been formally closed. |



Typical incident workflow:



```mermaid

flowchart TD

&#x20;   A\[OPEN] --> B\[INVESTIGATING]

&#x20;   B --> C\[CONTAINED]

&#x20;   C --> D\[RESOLVED]

&#x20;   D --> E\[CLOSED]

```



The application validates supported status values. The current implementation does not enforce a strict transition sequence; valid statuses can be selected independently.



\## 6. Alert-to-Incident Association



Security alerts can be linked to incident cases.



This enables an analyst to associate multiple relevant alerts with a single investigation.



For example, suspicious PowerShell execution and related authentication activity may be grouped under one incident.



The `incident\_alerts` table stores the relationships between incident records and alert records.



\## 7. Investigation Notes



Analysts can record investigation notes against an incident.



Each note includes:



\- Incident reference.

\- Analyst name.

\- Investigation note.

\- Timestamp.



Notes provide a record of observations, investigative steps, findings, and actions taken during incident handling.



\## 8. Evidence Register



MiniSOC provides an evidence registration feature for recording evidence metadata.



The evidence register supports:



| Field | Description |

|---|---|

| Evidence type | Type of evidence collected. |

| Description | Explanation of the evidence. |

| Collected by | Analyst responsible for collection. |

| File path | Location of the associated evidence file, when provided. |

| Timestamp | Evidence registration time. |



Example evidence types include:



\- Windows Event Logs.

\- Sysmon event exports.

\- Process execution records.

\- Network capture files.

\- Investigation screenshots.



\*\*Important limitation:\*\* The current implementation records evidence metadata and file paths. It does not automatically upload, copy, hash, validate, or preserve evidence files. It does not yet implement cryptographic integrity verification or a complete chain-of-custody workflow.



\## 9. Database Design



Incident response data is stored in SQLite.



The implementation uses four incident-related tables.



| Table | Purpose |

|---|---|

| `incidents` | Stores incident records and status information. |

| `incident\_alerts` | Associates alerts with incidents. |

| `incident\_notes` | Stores investigation notes. |

| `incident\_evidence` | Stores evidence metadata. |



The incident management module enables foreign-key enforcement on its database connections.



\### Data relationships



```mermaid

erDiagram

&#x20;   INCIDENTS ||--o{ INCIDENT\_ALERTS : contains

&#x20;   INCIDENTS ||--o{ INCIDENT\_NOTES : records

&#x20;   INCIDENTS ||--o{ INCIDENT\_EVIDENCE : registers

```



The `incident\_alerts` table also references the alert records stored by the alert management component.



\## 10. Dashboard Integration



Incident response functionality is integrated into the Streamlit dashboard.



The incident response workspace supports:



\- Incident creation.

\- Incident overview and history.

\- Analyst assignment.

\- Alert association.

\- Investigation notes.

\- Evidence metadata registration.

\- Status updates.

\- Linked alert review.

\- Investigation timeline and evidence register.



This provides a central interface for managing security investigations.



\## 11. Functional Validation



The incident management implementation underwent functional testing.



Validated scenarios included:



\- Successful incident creation.

\- Unique case ID generation.

\- Incident severity validation.

\- Supported status validation.

\- Alert-to-incident linking.

\- Investigation note creation.

\- Evidence metadata registration.

\- Incident status lifecycle updates.

\- Resolution information storage.

\- Rejection of invalid severity and status values.

\- Handling of missing incident and alert references.

\- SQLite database integrity.



The database integrity check returned:



`ok`



The final recorded database contained:



| Record type | Count |

|---|---:|

| Security alerts | 6 |

| Incidents | 3 |

| Incident-alert links | 2 |

| Investigation notes | 3 |

| Evidence records | 2 |



These counts represent the state at the time of the final validation check.



\## 12. Current Limitations



\- Status values are validated, but strict transition enforcement is not implemented.

\- Evidence files are not automatically copied or protected.

\- Evidence hashing and cryptographic integrity checks are not implemented.

\- A formal chain-of-custody process is not implemented.

\- Analyst identity and permissions are not integrated with an authentication system.

\- Incident handling is currently designed for a local SQLite deployment.



\## 13. Future Improvements



Planned improvements include:



\- Automated SHA-256 evidence hashing.

\- Evidence integrity verification.

\- Formal chain-of-custody records.

\- Strict incident transition validation.

\- Analyst authentication and role-based access control.

\- Incident response playbooks.

\- Automated alert-to-incident correlation.

\- Incident reporting and export.

\- Investigation audit trails.



\---



\*MiniSOC Incident Response — Case Management, Investigation Tracking, and Evidence Registration.\*
