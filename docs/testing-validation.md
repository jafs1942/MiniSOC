\# MiniSOC — Testing and Validation Report



\## 1. Purpose



This document records the functional testing and validation performed on MiniSOC.



Testing focused on detection accuracy, event processing, malformed input handling, authentication monitoring, incident management, dashboard functionality, and database integrity.



The project was tested using a combination of synthetic security events and real Windows endpoint telemetry.



\## 2. Testing Environment



| Component | Environment |

|---|---|

| Operating system | Windows |

| Python | 3.10.6 |

| Streamlit | 1.65.0 |

| Pandas | 2.3.3 |

| Database | SQLite |

| Endpoint telemetry | Sysmon |

| Authentication telemetry | Windows Security Event Logs |



\## 3. Detection Engine Testing



\### 3.1 Process Detection



The following detection scenarios were tested:



| Test scenario | Expected result | Validation |

|---|---|---|

| Encoded PowerShell command | HIGH alert | Real telemetry and synthetic regression |

| PowerShell execution policy bypass | HIGH alert | Real telemetry and synthetic regression |

| `wscript.exe` execution | MEDIUM alert | Real benign Sysmon telemetry |

| `cscript.exe` execution | MEDIUM alert | Synthetic test |

| `mshta.exe` execution | MEDIUM alert | Synthetic test |

| Office spawning PowerShell | HIGH alert | Synthetic test |

| Normal PowerShell activity | No alert | Synthetic regression |

| Normal Notepad execution | No alert | Synthetic regression |

| Normal Office application launch | No alert | Synthetic regression |

| Malformed event input | No crash | Synthetic robustness test |



\### 3.2 Detection Engine Hardening



The detection engine was tested against malformed event structures.



Scenarios included:



\- Non-list event batches.

\- Non-dictionary event entries.

\- Missing event data.

\- Invalid image fields.

\- Missing command-line values.

\- Missing parent process information.



\*\*Result:\*\* Malformed input was handled without an application crash.



\## 4. Authentication Detection Testing



\### 4.1 Brute-Force Detection



Configured threshold:



\- Three or more failed login attempts.

\- Same account.

\- Same source IP.

\- Within ten minutes.



| Test case | Expected result | Result |

|---|---|---|

| Three failures against one account within ten minutes | HIGH alert | PASS |

| Two failures against one account | No alert | PASS |

| Three failures spanning twelve minutes | No alert | PASS |

| Three failures at 10:00, 10:06, and 10:12 | No alert | PASS |



\### 4.2 Password Spraying Detection



Configured threshold:



\- Three or more distinct accounts.

\- Same source IP.

\- Within ten minutes.



| Test case | Expected result | Result |

|---|---|---|

| Three distinct accounts from one source IP | HIGH alert | PASS |

| Two distinct accounts | No alert | PASS |



\### 4.3 Successful Login Detection



The following scenarios were validated:



| Test case | Expected result | Validation |

|---|---|---|

| Remote interactive login, Logon Type 10 | MEDIUM alert | Synthetic test |

| External network login, Logon Type 3 | MEDIUM alert | Synthetic test |

| Successful login after qualifying brute force | HIGH alert | Synthetic integration test |

| Repeated matching successful logins | One correlation alert | Synthetic test |

| Private IP address | Excluded from external IP alert | Synthetic test |

| Loopback IP address | Excluded from external IP alert | Synthetic test |

| Mismatched account or source IP | No correlation alert | Synthetic test |

| Success before qualifying failures | No correlation alert | Synthetic test |



Real Windows authentication telemetry was also observed during monitoring. Normal successful logons and a deliberately generated failed login were inspected.



A real brute-force burst, external network login, and Remote Desktop login were not generated for validation.



\## 5. Event Collection Testing



The collection layer was tested for both baseline and incremental collection.



Validation included:



\- Sysmon process event collection.

\- Windows Security Event ID 4624 collection.

\- Windows Security Event ID 4625 collection.

\- Event record ID ordering.

\- Incremental collection after a specified record ID.

\- Separate failed and successful login baseline collection.

\- Timestamp parsing.

\- Handling of empty incremental batches.



\### Collection results



Tests confirmed that:



\- Returned incremental records were newer than the supplied cursor.

\- Events were returned in ascending record ID order.

\- Separate baseline collection retrieved the expected authentication event types.

\- Empty incremental results were handled without error.



A full high-volume backlog stress test has not yet been performed.



\## 6. Monitoring Integration Testing



The monitoring engine was tested using synthetic events and actual Windows event collection.



\### Synthetic integration scenario



A sequence of three failed authentication attempts followed by a matching successful login was processed.



Expected results:



1\. A brute-force alert.

2\. A successful-login-after-brute-force alert.

3\. Correct event ordering and cursor advancement.



\*\*Result:\*\* Both expected HIGH alerts were generated, and the processing cursor advanced to the final event record.



\### Live monitoring scenario



The monitoring engine was executed against the Windows endpoint.



Observed results included:



\- Successful initialization.

\- Sysmon baseline collection.

\- Failed and successful login baseline collection.

\- Five-second polling cycles.

\- Sysmon event processing and noise filtering.

\- Successful processing of a Windows Security Event ID 4624 service logon.

\- Incremental cursor advancement.

\- Clean monitoring shutdown.



The observed SYSTEM Logon Type 5 event was a service logon and did not generate a security alert.



No suspicious activity was detected during this particular live monitoring session.



\## 7. Dashboard Testing



The Streamlit dashboard was tested for:



\- Alert metric display.

\- HIGH severity filtering.

\- MEDIUM severity filtering.

\- Search by detection details.

\- Search by process name.

\- Time-based filtering.

\- CSV export.

\- Detection rule statistics.

\- Incident response workspace functionality.



\### Observed results



| Test | Observed result |

|---|---|

| HIGH severity filter | 5 alerts |

| MEDIUM severity filter | 1 alert |

| PowerShell search | 4 alerts |

| `wscript.exe` search | 1 alert |

| All-time filter | 6 alerts |

| Last 24 hours filter | 3 alerts |

| Last 7 days filter | 6 alerts |

| Last 30 days filter | 6 alerts |

| CSV export | Successful |



These results reflect the database state at the time of dashboard testing.



\## 8. Incident Management Testing



The incident management implementation was tested for:



\- Incident creation.

\- Unique case identifier generation.

\- Severity validation.

\- Status validation.

\- Alert association.

\- Investigation note creation.

\- Evidence metadata registration.

\- Analyst assignment.

\- Incident lifecycle updates.

\- Resolution information storage.

\- Missing incident and alert rejection.



The lifecycle test covered:



`OPEN → INVESTIGATING → CONTAINED → RESOLVED → CLOSED`



All tested operations completed successfully.



The implementation validates allowed status values but does not enforce a strict transition sequence.



\## 9. Database Integrity Testing



A read-only SQLite integrity check was performed after monitoring and synthetic integration testing.



Final observed results:



| Database item | Count |

|---|---:|

| Alerts | 6 |

| Incidents | 3 |

| Incident-alert links | 2 |

| Investigation notes | 3 |

| Evidence records | 2 |



SQLite integrity check:



`ok`



The database retained the expected records after testing.



\## 10. Overall Validation Summary



| Testing area | Outcome |

|---|---|

| Process detection logic | Passed tested scenarios |

| Authentication detection | Passed synthetic scenarios |

| Malformed event handling | Passed |

| Timestamp parsing | Passed |

| Incremental event collection | Passed tested batches |

| Monitoring initialization | Passed |

| Synthetic event correlation | Passed |

| Live monitoring execution | Passed |

| Dashboard functionality | Passed tested features |

| Incident management | Passed tested operations |

| SQLite integrity | Passed |



\## 11. Known Testing Limitations



The validation performed does not establish complete production readiness.



Outstanding areas include:



\- Real brute-force attack telemetry validation.

\- Real Remote Desktop authentication validation.

\- Real external network login validation.

\- Real Office-to-PowerShell process telemetry validation.

\- High-volume event backlog stress testing.

\- Persistent cursor recovery across restarts.

\- Automated evidence hashing and chain-of-custody validation.



Synthetic tests validate detection logic under controlled conditions but do not replace validation against representative real-world attack telemetry.



\## 12. Conclusion



The MiniSOC implementation successfully demonstrated its core monitoring, detection, alert management, dashboard, and incident-response workflows.



Testing confirmed that selected detection rules operate as expected, malformed inputs are handled safely, incremental collection works for tested batches, dashboard features are functional, and SQLite records remain intact.



The project provides a practical foundation for further development in Windows security monitoring, detection engineering, and incident response automation.



\---



\*MiniSOC Testing and Validation — Functional Testing, Detection Verification, and Database Integrity.\*
