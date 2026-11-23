
from event_collector import collect_sysmon_events
from alert_store import initialize_database, save_alerts


def analyze_events(events):
    alerts = []

    if not isinstance(events, (list, tuple)):
        return alerts

    for event in events:

        # Validate event structure
        if not isinstance(event, dict):
            continue

        data = event.get("Data")

        if not isinstance(data, dict):
            continue

        # Safely extract and normalize event fields
        process_value = data.get("Image")
        command_value = data.get("CommandLine")
        parent_value = data.get("ParentImage")

        if not isinstance(process_value, str):
            continue

        process = process_value.lower()

        command = (
            command_value
            if isinstance(command_value, str)
            else ""
        )

        command_lower = command.lower()

        parent = (
            parent_value.lower()
            if isinstance(parent_value, str)
            else ""
        )

        # Rule 1: Encoded PowerShell
        if "powershell.exe" in process:
            if (
                "-enc" in command_lower
                or "-encodedcommand" in command_lower
            ):
                alerts.append({
                    "severity": "HIGH",
                    "rule": "Encoded PowerShell Command",
                    "process": process,
                    "command": command
                })

        # Rule 2: Execution policy bypass
        if "powershell.exe" in process:
            if "executionpolicy bypass" in command_lower:
                alerts.append({
                    "severity": "HIGH",
                    "rule": "PowerShell Execution Policy Bypass",
                    "process": process,
                    "command": command
                })

        # Rule 3: Suspicious script interpreters
        if any(x in process for x in [
            "wscript.exe",
            "cscript.exe",
            "mshta.exe"
        ]):
            alerts.append({
                "severity": "MEDIUM",
                "rule": "Suspicious Script Interpreter",
                "process": process,
                "command": command
            })

        # Rule 4: Office spawning PowerShell
        office_apps = [
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe"
        ]

        if "powershell.exe" in process:
            if any(x in parent for x in office_apps):
                alerts.append({
                    "severity": "HIGH",
                    "rule": "Office Spawned PowerShell",
                    "process": process,
                    "command": command
                })

    return alerts


if __name__ == "__main__":

    print("\n======================================")
    print("       MINISOC DETECTION ENGINE")
    print("======================================")

    initialize_database()

    print("\nCollecting Windows security events...")

    events = collect_sysmon_events(limit=20)

    print("Events collected:", len(events))

    alerts = analyze_events(events)

    print("Events analyzed:", len(events))
    print("Alerts generated:", len(alerts))

    if alerts:
        print("\n========== SECURITY ALERTS ==========")

        for number, alert in enumerate(alerts, start=1):
            print(f"\nALERT #{number}")
            print("Severity:", alert["severity"])
            print("Detection:", alert["rule"])
            print("Process:", alert["process"])

        save_alerts(alerts)

    else:
        print("\nNo suspicious activity detected in this batch.")

    print("\nMINISOC ANALYSIS COMPLETED")
