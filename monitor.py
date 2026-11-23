
import json
import subprocess
import time
from datetime import datetime, timedelta

from detection_engine import analyze_events

from security_collector import (
    collect_security_events,
    collect_failed_logins,
    collect_successful_logins
)

from login_detector import (
    detect_brute_force,
    parse_event_time,
    TIME_WINDOW_MINUTES
)

from successful_login_detector import (
    detect_remote_interactive_logins,
    detect_external_network_logins,
    detect_success_after_brute_force
)

from alert_store import initialize_database, save_alerts


# =========================================================
# CONFIGURATION
# =========================================================

POLL_INTERVAL = 5

MAX_SYSMON_EVENTS = 100
MAX_SECURITY_EVENTS = 500

last_sysmon_record = 0
last_security_record = 0

recent_login_events = []
alerted_login_sources = set()

NOISY_PROCESS_NAMES = {"secocl64.exe"}

COLLECTOR_MARKERS = (
    "get-winevent",
    "microsoft-windows-sysmon/operational",
    "logname = 'security'",
)


# =========================================================
# SYSMON EVENT COLLECTION
# =========================================================

def collect_sysmon_events(
    after_record_id=0,
    limit=MAX_SYSMON_EVENTS,
    mode="incremental"
):
    """
    Collect Sysmon Event ID 1.

    baseline:
        Retrieve the newest matching records.

    incremental:
        Retrieve the oldest unseen records after the cursor.
    """

    if mode not in ("baseline", "incremental"):
        raise ValueError("Mode must be baseline or incremental.")

    after_record_id = max(0, int(after_record_id))
    limit = max(1, min(int(limit), 5000))

    if mode == "baseline":

        script = r"""
        Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Sysmon/Operational'
            Id = 1
        } -MaxEvents LIMIT -ErrorAction SilentlyContinue |
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            $data = @{}

            foreach ($item in $xml.Event.EventData.Data) {
                $data[$item.Name] = $item.'#text'
            }

            [PSCustomObject]@{
                RecordId = $_.RecordId
                EventId = $_.Id
                TimeCreated = $_.TimeCreated.ToString('o')
                Data = $data
            }
        } | ConvertTo-Json -Depth 5
        """

    else:

        script = r"""
        Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' `
            -FilterXPath "*[System[(EventID=1) and (EventRecordID > AFTER_RECORD_ID)]]" `
            -Oldest `
            -MaxEvents LIMIT `
            -ErrorAction SilentlyContinue |
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            $data = @{}

            foreach ($item in $xml.Event.EventData.Data) {
                $data[$item.Name] = $item.'#text'
            }

            [PSCustomObject]@{
                RecordId = $_.RecordId
                EventId = $_.Id
                TimeCreated = $_.TimeCreated.ToString('o')
                Data = $data
            }
        } | ConvertTo-Json -Depth 5
        """

        script = script.replace(
            "AFTER_RECORD_ID",
            str(after_record_id)
        )

    script = script.replace("LIMIT", str(limit))

    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            if result.stderr.strip():
                print("[SYSMON WARNING]", result.stderr.strip())

            return []

        if not result.stdout.strip():
            return []

        events = json.loads(result.stdout)

        if isinstance(events, dict):
            events = [events]

        return sorted(
            events,
            key=lambda event: int(event.get("RecordId", 0))
        )

    except subprocess.TimeoutExpired:
        print("[SYSMON WARNING] Collection timed out.")

    except json.JSONDecodeError as error:
        print("[SYSMON WARNING] Invalid JSON:", error)

    except Exception as error:
        print("[SYSMON ERROR]", error)

    return []


# =========================================================
# NOISE FILTERING
# =========================================================

def is_noise_event(event):

    data = event.get("Data", {}) or {}

    image = str(
        data.get("Image", "")
    ).replace("/", "\\").lower()

    process_name = image.rsplit("\\", 1)[-1]

    command = str(
        data.get("CommandLine", "")
    ).lower()

    if process_name in NOISY_PROCESS_NAMES:
        return True

    if process_name == "powershell.exe" and any(
        marker in command for marker in COLLECTOR_MARKERS
    ):
        return True

    return False


# =========================================================
# ALERT HANDLING
# =========================================================

def save_and_display_alerts(alerts):

    if not alerts:
        return

    print("\n" + "!" * 55)
    print("             SECURITY ALERT DETECTED")
    print("!" * 55)

    for alert in alerts:

        print("\nSeverity:", alert.get("severity", "UNKNOWN"))
        print("Detection:", alert.get("rule", "Unknown"))
        print("Source:", alert.get("process", "Unknown"))
        print("Details:", alert.get("command", ""))

    saved = save_alerts(alerts)

    print("\nNew alerts saved:", saved)
    print("Refresh the SOC dashboard to view them.")
    print("!" * 55)


# =========================================================
# PROCESS EVENT INVESTIGATION
# =========================================================

def investigate_process_event(event):

    data = event.get("Data", {}) or {}

    print("\n[NEW PROCESS EVENT]")
    print("Process:", data.get("Image", "Unknown"))
    print("Command:", data.get("CommandLine", "Unknown"))

    alerts = analyze_events([event])

    save_and_display_alerts(alerts)


# =========================================================
# LOGIN EVENT MANAGEMENT
# =========================================================

def prune_recent_login_events():

    global recent_login_events

    cutoff = datetime.now().astimezone() - timedelta(
        minutes=TIME_WINDOW_MINUTES
    )

    valid_events = []

    for event in recent_login_events:

        event_time = parse_event_time(
            event.get("TimeCreated")
        )

        if event_time is not None and event_time >= cutoff:
            valid_events.append(event)

    recent_login_events = valid_events


# =========================================================
# FAILED LOGIN PROCESSING
# =========================================================

def process_failed_login(event):

    recent_login_events.append(event)

    print("\n[FAILED LOGIN EVENT]")
    print("Account:", event.get("Account"))
    print("Source IP:", event.get("SourceIP"))
    print("Logon Type:", event.get("LogonType"))
    print("Time:", event.get("TimeCreated"))

    prune_recent_login_events()

    alerts = detect_brute_force(
        recent_login_events
    )

    new_alerts = []

    for alert in alerts:

        signature = (
            alert.get("process", ""),
            alert.get("command", "")
        )

        if signature not in alerted_login_sources:

            alerted_login_sources.add(signature)
            new_alerts.append(alert)

    save_and_display_alerts(new_alerts)


# =========================================================
# SUCCESSFUL LOGIN PROCESSING
# =========================================================

def process_successful_login(event):

    print("\n[SUCCESSFUL LOGIN EVENT]")
    print("Account:", event.get("Account"))
    print("Domain:", event.get("Domain"))
    print("Logon Type:", event.get("LogonType"))
    print("Source IP:", event.get("SourceIP"))
    print("Workstation:", event.get("Workstation"))
    print("Time:", event.get("TimeCreated"))

    prune_recent_login_events()

    alerts = []

    alerts.extend(
        detect_remote_interactive_logins([event])
    )

    alerts.extend(
        detect_external_network_logins([event])
    )

    alerts.extend(
        detect_success_after_brute_force(
            [event],
            recent_login_events
        )
    )

    save_and_display_alerts(alerts)


# =========================================================
# STARTUP BASELINE
# =========================================================

def initialize_monitoring():

    global last_sysmon_record
    global last_security_record
    global recent_login_events

    print("\nInitializing Sysmon and Windows Security logs...")

    # Retrieve the newest Sysmon events for startup baseline.
    sysmon_events = collect_sysmon_events(
        after_record_id=0,
        limit=MAX_SYSMON_EVENTS,
        mode="baseline"
    )

    # Retrieve the newest failed logins independently.
    failed_events = collect_failed_logins(
        limit=MAX_SECURITY_EVENTS,
        mode="baseline"
    )

    # Retrieve the newest successful logins independently.
    successful_events = collect_successful_logins(
        limit=MAX_SECURITY_EVENTS,
        mode="baseline"
    )

    if not sysmon_events:

        print("[ERROR] Sysmon collection unavailable.")
        return False

    last_sysmon_record = max(
        int(event.get("RecordId", 0))
        for event in sysmon_events
    )

    security_events = failed_events + successful_events

    if security_events:

        last_security_record = max(
            int(event.get("RecordId", 0))
            for event in security_events
        )

    # Retain only recent failed logins for correlation.
    # Historical events do not generate startup alerts.

    cutoff = datetime.now().astimezone() - timedelta(
        minutes=TIME_WINDOW_MINUTES
    )

    recent_login_events = []

    for event in failed_events:

        event_time = parse_event_time(
            event.get("TimeCreated")
        )

        if event_time is not None and event_time >= cutoff:
            recent_login_events.append(event)

    print("\n[SUCCESS] Monitoring initialized.")

    print("Sysmon starting record:", last_sysmon_record)
    print("Security starting record:", last_security_record)

    print("\nBaseline collected:")

    print("Failed login events:", len(failed_events))
    print("Successful login events:", len(successful_events))

    print(
        "Recent failed logins retained:",
        len(recent_login_events)
    )

    return True


# =========================================================
# MAIN MONITORING LOOP
# =========================================================

def main():

    global last_sysmon_record
    global last_security_record

    print("=" * 60)
    print("                 MINISOC UNIFIED MONITOR")
    print("=" * 60)

    initialize_database()

    if not initialize_monitoring():
        return

    print("\nPolling interval:", POLL_INTERVAL, "seconds")

    print("\nMonitoring:")

    print("- Sysmon process creation (Event ID 1)")
    print("- Encoded PowerShell")
    print("- PowerShell execution policy bypass")
    print("- Suspicious script interpreters")
    print("- Office spawning PowerShell")
    print("- Failed logins (Security Event ID 4625)")
    print("- Successful logins (Security Event ID 4624)")
    print("- Brute-force detection")
    print("- Remote interactive logins")
    print("- External network logins")
    print("- Successful login following brute force")
    print("- Time-bounded alert deduplication")

    print("\nPress CTRL + C to stop.")

    try:

        while True:

            # -----------------------------------------
            # SYSMON PROCESS EVENTS
            # -----------------------------------------

            sysmon_events = collect_sysmon_events(
                after_record_id=last_sysmon_record,
                limit=MAX_SYSMON_EVENTS,
                mode="incremental"
            )

            visible_count = 0
            suppressed_count = 0

            for event in sysmon_events:

                record_id = int(
                    event.get("RecordId", 0)
                )

                if record_id <= last_sysmon_record:
                    continue

                if is_noise_event(event):

                    suppressed_count += 1

                else:

                    visible_count += 1
                    investigate_process_event(event)

                # Advance only after this event is handled.
                last_sysmon_record = record_id

            # -----------------------------------------
            # WINDOWS SECURITY EVENTS
            # -----------------------------------------

            security_events = collect_security_events(
                event_ids=(4624, 4625),
                after_record_id=last_security_record,
                limit=MAX_SECURITY_EVENTS,
                mode="incremental"
            )

            new_security_events = 0

            for event in security_events:

                record_id = int(
                    event.get("RecordId", 0)
                )

                if record_id <= last_security_record:
                    continue

                event_id = event.get("EventId")

                if event_id == 4625:

                    process_failed_login(event)

                elif event_id == 4624:

                    process_successful_login(event)

                else:

                    continue

                # Advance after processing this event.
                last_security_record = record_id

                new_security_events += 1

            # -----------------------------------------
            # MONITOR STATUS
            # -----------------------------------------

            print(
                f"\n[{datetime.now():%H:%M:%S}] "
                f"Monitoring | "
                f"New Sysmon: {visible_count} | "
                f"Noise filtered: {suppressed_count} | "
                f"New Security events: {new_security_events} | "
                f"Recent failed logins: {len(recent_login_events)}"
            )

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:

        print("\n\nMini SOC monitoring stopped.")

        print("Last Sysmon record:", last_sysmon_record)
        print("Last Security record:", last_security_record)


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":
    main()
