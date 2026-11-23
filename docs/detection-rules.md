\# MiniSOC — Detection Engineering Documentation



\## 1. Overview



MiniSOC implements custom Python-based detection rules to identify suspicious process execution and authentication activity on a Windows endpoint.



The detection engine analyzes Sysmon process creation events and Windows Security Event Logs to identify potentially malicious behavior.



Detection rules generate structured alerts with severity classifications to support security monitoring and investigation.



\## 2. Detection Rule Summary



| ID | Detection Rule | Severity | Primary Telemetry |

|---|---|---|---|

| DET-001 | Encoded PowerShell Execution | HIGH | Sysmon Event ID 1 |

| DET-002 | PowerShell Execution Policy Bypass | HIGH | Sysmon Event ID 1 |

| DET-003 | Suspicious Script Interpreter | MEDIUM | Sysmon Event ID 1 |

| DET-004 | Office Application Spawning PowerShell | HIGH | Sysmon Event ID 1 |

| DET-005 | Brute Force Attack - Single Account | HIGH | Security Event ID 4625 |

| DET-006 | Password Spraying Attack | HIGH | Security Event ID 4625 |

| DET-007 | Successful Login After Brute Force | HIGH | Security Event IDs 4625 and 4624 |

| DET-008 | Remote Interactive Login | MEDIUM | Security Event ID 4624 |

| DET-009 | External Network Login | MEDIUM | Security Event ID 4624 |



\---



\## 3. Process-Based Detection Rules



\### DET-001: Encoded PowerShell Execution



\*\*Severity:\*\* HIGH



\*\*Telemetry source:\*\* Sysmon Event ID 1 — Process Creation.



\*\*Objective:\*\* Identify PowerShell processes using encoded command execution.



\*\*Detection logic:\*\*



The rule examines process command-line arguments for encoded PowerShell execution indicators, including encoded command parameters.



Encoded commands can conceal script content and make command-line inspection more difficult.



\*\*Security relevance:\*\*



Attackers may use encoded PowerShell commands to obscure malicious scripts, execute payloads, or evade basic security monitoring.



\*\*Validation:\*\* Tested using real Sysmon process telemetry and synthetic regression events.



\### DET-002: PowerShell Execution Policy Bypass



\*\*Severity:\*\* HIGH



\*\*Telemetry source:\*\* Sysmon Event ID 1.



\*\*Objective:\*\* Identify PowerShell execution using execution policy bypass parameters.



\*\*Detection logic:\*\*



The rule inspects PowerShell command-line arguments for execution policy bypass indicators.



\*\*Security relevance:\*\*



Execution policy bypass may be used to run scripts without the normal PowerShell execution policy restrictions.



It is a suspicious indicator, although legitimate administrators and automation tools may also use this option.



\*\*Validation:\*\* Tested using real Sysmon process telemetry and synthetic regression events.



\### DET-003: Suspicious Script Interpreter Execution



\*\*Severity:\*\* MEDIUM



\*\*Telemetry source:\*\* Sysmon Event ID 1.



\*\*Objective:\*\* Detect execution of potentially abused Windows script interpreters.



\*\*Monitored interpreters:\*\*



\- `wscript.exe`

\- `cscript.exe`

\- `mshta.exe`



\*\*Detection logic:\*\*



The rule examines process image paths and identifies execution involving the monitored script interpreters.



\*\*Security relevance:\*\*



These Windows utilities can execute scripts and application content. They may be abused to execute malicious code or establish persistence.



\*\*Validation:\*\* Tested using real Sysmon process telemetry with benign `wscript.exe` execution, alongside synthetic regression tests for the interpreter detection logic.



\### DET-004: Office Application Spawning PowerShell



\*\*Severity:\*\* HIGH



\*\*Telemetry source:\*\* Sysmon Event ID 1.



\*\*Objective:\*\* Identify Microsoft Office applications launching PowerShell.



\*\*Detection logic:\*\*



The rule examines parent process and child process information to identify PowerShell launched by Office applications.



\*\*Security relevance:\*\*



Malicious Office documents and macro-enabled content may abuse trusted Office applications to launch scripting interpreters.



\*\*Validation:\*\* Detection logic validated using synthetic process events. Real Office-to-PowerShell attack telemetry has not yet been validated.



\---



\## 4. Authentication-Based Detection Rules



\### DET-005: Brute Force Attack - Single Account



\*\*Severity:\*\* HIGH



\*\*Telemetry source:\*\* Windows Security Event ID 4625 — Failed Logon.



\*\*Objective:\*\* Detect repeated failed authentication attempts against a single account.



\*\*Detection threshold:\*\*



\- At least 3 failed login attempts.

\- Same account.

\- Same source IP address.

\- Within a 10-minute time window.



\*\*Security relevance:\*\*



Repeated authentication failures may indicate password guessing or brute-force activity.



\*\*Validation:\*\* Synthetic event testing confirmed that three qualifying failures trigger an alert, while attempts below the threshold or outside the time window do not.



\### DET-006: Password Spraying Attack



\*\*Severity:\*\* HIGH



\*\*Telemetry source:\*\* Windows Security Event ID 4625.



\*\*Objective:\*\* Identify authentication failures against multiple accounts from the same source IP address.



\*\*Detection threshold:\*\*



\- At least 3 distinct accounts.

\- Same source IP address.

\- Within a 10-minute time window.



\*\*Security relevance:\*\*



Password spraying involves trying a limited number of passwords against multiple accounts instead of repeatedly targeting one account.



\*\*Validation:\*\* Synthetic event testing confirmed detection of three distinct accounts from one source IP and rejected attempts below the threshold.



\### DET-007: Successful Login After Brute Force



\*\*Severity:\*\* HIGH



\*\*Telemetry sources:\*\*

\- Event ID 4625 — Failed Logon.

\- Event ID 4624 — Successful Logon.



\*\*Objective:\*\* Identify a successful authentication following repeated failed login attempts.



\*\*Detection logic:\*\*



The correlation rule checks whether:



1\. At least three failed attempts occurred.

2\. The failures involved the same account and source IP.

3\. The failures occurred within the configured 10-minute window.

4\. A subsequent successful login matched the same account and source IP.



Duplicate correlation alerts are suppressed for the same matching failure set.



\*\*Security relevance:\*\*



A successful login following repeated authentication failures may indicate that an attacker eventually guessed or obtained valid credentials.



\*\*Validation:\*\* Synthetic integration testing confirmed that three failed attempts followed by a matching successful login generate the expected HIGH alert. Duplicate successful logins did not produce duplicate correlation alerts.



\### DET-008: Remote Interactive Login



\*\*Severity:\*\* MEDIUM



\*\*Telemetry source:\*\* Windows Security Event ID 4624.



\*\*Objective:\*\* Identify successful remote interactive logons.



\*\*Detection logic:\*\*



The rule identifies successful logon events with:



`Logon Type 10`



Logon Type 10 represents RemoteInteractive authentication, commonly associated with Remote Desktop connections.



\*\*Security relevance:\*\*



Unexpected remote interactive logons may indicate unauthorized remote access or misuse of legitimate credentials.



\*\*Validation:\*\* Synthetic Security Event testing confirmed the expected detection behavior. Real Remote Desktop authentication telemetry has not yet been validated.



\### DET-009: External Network Login



\*\*Severity:\*\* MEDIUM



\*\*Telemetry source:\*\* Windows Security Event ID 4624.



\*\*Objective:\*\* Identify successful network logons originating from globally routable external IP addresses.



\*\*Detection logic:\*\*



The rule evaluates:



\- Successful authentication events.

\- Logon Type 3.

\- Source IP address classification.



Python's `ipaddress` module is used to distinguish globally routable addresses from private, loopback, link-local, multicast, and invalid addresses.



\*\*Security relevance:\*\*



Unexpected external network authentication may indicate unauthorized access or suspicious remote authentication activity.



\*\*Validation:\*\* Synthetic event testing confirmed detection of qualifying external IP addresses and exclusion of private and loopback addresses. Real external network authentication telemetry has not yet been validated.



\---



\## 5. Severity Classification



MiniSOC uses three alert severity levels.



| Severity | Meaning |

|---|---|

| HIGH | Activity requiring priority investigation. |

| MEDIUM | Suspicious activity requiring analyst review. |

| LOW | Lower-priority security observations. |



Severity represents the configured detection rule classification. It does not independently establish that an attack was successful.



\## 6. Detection Processing Workflow



1\. Windows generates Sysmon or Security Event Log records.

2\. The collection modules retrieve relevant events.

3\. The monitoring engine routes events to the appropriate detection modules.

4\. Detection rules evaluate event attributes and correlation conditions.

5\. Matching events produce structured alerts.

6\. Alerts are stored in SQLite.

7\. Analysts review alerts through the Streamlit dashboard.

8\. Relevant alerts can be linked to incidents for investigation.



\## 7. Testing and Validation Summary



The detection engine underwent functional testing using synthetic events and selected real Windows endpoint telemetry.



| Detection capability | Validation evidence |

|---|---|

| Encoded PowerShell | Real Sysmon telemetry and synthetic regression tests |

| Execution policy bypass | Real Sysmon telemetry and synthetic regression tests |

| Script interpreter execution | Real benign Sysmon telemetry and synthetic tests |

| Office spawning PowerShell | Synthetic process events |

| Single-account brute force | Synthetic authentication events |

| Password spraying | Synthetic authentication events |

| Successful login after brute force | Synthetic correlation and integration tests |

| Remote interactive login | Synthetic authentication events |

| External network login | Synthetic authentication events |



Additional testing covered malformed event handling, missing fields, timestamp parsing, duplicate correlation suppression, and detection regression behavior.



\## 8. Known Detection Limitations



\- Detection rules are based on defined event attributes and thresholds; they do not establish malicious intent on their own.

\- The brute-force and password-spraying thresholds are configurable detection assumptions, not universal attack indicators.

\- Remote interactive and external network login detections require further validation using representative real-world telemetry.

\- Office-to-PowerShell detection has not yet been validated with a real Office-generated process event.

\- Logon Type 3 and Type 10 detections may require additional contextual filtering to reduce false positives.

\- Source metadata for some correlated alerts may be incomplete.

\- Detection coverage is currently focused on the implemented Windows telemetry sources.



\## 9. Future Detection Engineering Improvements



\- MITRE ATT\&CK technique mapping.

\- Parent-child process relationship enrichment.

\- User and host context enrichment.

\- Configurable detection thresholds.

\- Detection tuning and false-positive reduction.

\- Additional Windows Security Event IDs.

\- Detection rule versioning and automated regression testing.

\- Improved alert context and investigation evidence.



\---



\*MiniSOC Detection Engineering — Windows Security Monitoring and Threat Detection.\*
