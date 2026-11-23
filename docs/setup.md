\# MiniSOC — Installation and Setup Guide



\## 1. Introduction



This guide explains how to install, configure, and run MiniSOC on a Windows endpoint.



MiniSOC uses Python, Sysmon, Windows Security Event Logs, SQLite, and Streamlit.



\## 2. Prerequisites



\- Windows 10 or Windows 11.

\- Python 3.10 or later.

\- PowerShell.

\- Git.

\- Sysmon installed and configured.

\- Permission to read Windows Security Event Logs.



Administrator privileges may be required for event collection.



\## 3. Clone the Repository



```powershell

git clone YOUR\_GITHUB\_REPOSITORY\_URL

cd MiniSoc

```



\## 4. Install Dependencies



Install the required Python packages:



```powershell

python -m pip install -r requirements.txt

```



The project currently specifies:



\- Streamlit 1.65.0

\- Pandas 2.3.3



\## 5. Configure Sysmon



Install Sysmon from Microsoft's Sysinternals suite and configure it to collect process creation events.



MiniSOC currently uses Sysmon Event ID 1 for process creation monitoring.



Confirm that the Sysmon service is running and that events are being written to:



`Microsoft-Windows-Sysmon/Operational`



\## 6. Windows Security Event Logs



MiniSOC monitors the following Windows Security events:



| Event ID | Description |

|---|---|

| 4624 | Successful logon |

| 4625 | Failed logon |



Ensure that the Windows Security audit policy generates the required authentication events.



The monitoring account must have permission to read the Security event log.



\## 7. Start MiniSOC



\### Start the monitoring engine



```powershell

python main.py monitor

```



The monitoring engine initializes the local SQLite database, collects baseline events, and begins polling for new events.



\### Start the dashboard



Open another PowerShell terminal in the project directory:



```powershell

python main.py dashboard

```



Open the dashboard in your browser:



`http://localhost:8501`



\## 8. Database



MiniSOC uses SQLite for local alert and incident storage.



The database is created locally by the application.



Database files are excluded from version control to prevent accidental publication of endpoint telemetry and investigation records.



\## 9. Troubleshooting



\### Python module not found



Install dependencies again:



```powershell

python -m pip install -r requirements.txt

```



\### Access denied when reading Security logs



Run PowerShell with appropriate privileges and verify that the account can access the Windows Security event log.



\### No events returned



Check that:



\- Sysmon is installed and running.

\- The required event channels are enabled.

\- Windows is generating the expected events.

\- The monitoring account has the necessary permissions.



\### Dashboard does not start



Check the Streamlit installation:



```powershell

python -m pip show streamlit

```



Then launch directly:



```powershell

python -m streamlit run dashboard.py

```



\### Port 8501 is already in use



Stop the other Streamlit process or use another available port:



```powershell

python -m streamlit run dashboard.py --server.port 8502

```



\## 10. Security Considerations



\- Run MiniSOC only on authorized systems.

\- Protect local databases and investigation records.

\- Do not publish real endpoint logs or sensitive evidence.

\- Use appropriate permissions when collecting Security event logs.

\- Review alerts before treating them as confirmed security incidents.



\## 11. Current Implementation Notes



\- Event-processing cursors are maintained in memory.

\- Startup collection uses bounded baseline batches.

\- Evidence registration stores metadata and file paths.

\- Some detection scenarios have been validated using synthetic events.



Refer to `architecture.md`, `detection-rules.md`, and `testing-validation.md` for further technical information.



\---



\*MiniSOC Installation and Setup Guide.\*
