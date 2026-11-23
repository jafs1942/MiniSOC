
import subprocess
import json


def collect_security_events(
    event_ids=(4624, 4625),
    after_record_id=0,
    limit=500,
    mode="incremental"
):
    """Collect Windows Security events in baseline or incremental mode."""

    if isinstance(event_ids, int):
        event_ids = (event_ids,)

    event_ids = tuple(int(event_id) for event_id in event_ids)

    if not event_ids or any(
        event_id not in (4624, 4625) for event_id in event_ids
    ):
        raise ValueError("Only Security Event IDs 4624 and 4625 are supported.")

    if mode not in ("baseline", "incremental"):
        raise ValueError("Mode must be 'baseline' or 'incremental'.")

    after_record_id = max(0, int(after_record_id))
    limit = max(1, min(int(limit), 5000))

    event_filter = " or ".join(
        f"EventID={event_id}" for event_id in event_ids
    )

    order_option = "-Oldest" if mode == "incremental" else ""

    record_filter = (
        f" and (EventRecordID > {after_record_id})"
        if mode == "incremental"
        else ""
    )

    powershell_script = r"""
    $events = @(
        Get-WinEvent -LogName 'Security' `
            -FilterXPath "*[System[(EVENT_FILTER)RECORD_FILTER]]" `
            ORDER_OPTION `
            -MaxEvents LIMIT `
            -ErrorAction SilentlyContinue
    )

    $results = @(
        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            $data = @{}

            foreach ($item in $xml.Event.EventData.Data) {
                $data[$item.Name] = $item.'#text'
            }

            [PSCustomObject]@{
                RecordId = $event.RecordId
                TimeCreated = $event.TimeCreated.ToString("o")
                EventId = $event.Id
                Account = $data['TargetUserName']
                Domain = $data['TargetDomainName']
                LogonType = $data['LogonType']
                FailureReason = $data['FailureReason']
                Status = $data['Status']
                SubStatus = $data['SubStatus']
                SourceIP = $data['IpAddress']
                SourcePort = $data['IpPort']
                Authentication = $data['AuthenticationPackageName']
                LogonProcess = $data['LogonProcessName']
                Workstation = $data['WorkstationName']
                ProcessName = $data['ProcessName']
                TargetLogonId = $data['TargetLogonId']
                ElevatedToken = $data['ElevatedToken']
            }
        }
    )

    ConvertTo-Json -InputObject @($results) -Depth 5 -Compress
    """

    powershell_script = (
        powershell_script
        .replace("EVENT_FILTER", event_filter)
        .replace("RECORD_FILTER", record_filter)
        .replace("ORDER_OPTION", order_option)
        .replace("LIMIT", str(limit))
    )

    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", powershell_script],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            print("[SECURITY WARNING]", result.stderr.strip())
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
        print("[SECURITY WARNING] Collection timed out.")
    except json.JSONDecodeError as error:
        print("[SECURITY WARNING] Invalid JSON:", error)
    except Exception as error:
        print("[SECURITY ERROR]", error)

    return []


def collect_failed_logins(
    limit=20,
    after_record_id=0,
    mode="incremental"
):
    """Collect failed logins (Event ID 4625)."""
    return collect_security_events(
        event_ids=4625,
        after_record_id=after_record_id,
        limit=limit,
        mode=mode
    )


def collect_successful_logins(
    limit=20,
    after_record_id=0,
    mode="incremental"
):
    """Collect successful logins (Event ID 4624)."""
    return collect_security_events(
        event_ids=4624,
        after_record_id=after_record_id,
        limit=limit,
        mode=mode
    )


if __name__ == "__main__":
    print("\n======================================")
    print("       MINISOC SECURITY COLLECTOR")
    print("======================================")

    events = collect_security_events(
        event_ids=(4624, 4625),
        limit=20,
        mode="baseline"
    )

    failed_events = [
        event for event in events if event.get("EventId") == 4625
    ]

    successful_events = [
        event for event in events if event.get("EventId") == 4624
    ]

    print("\nFailed login events (4625):", len(failed_events))
    print("Successful login events (4624):", len(successful_events))

    for event in events:
        print("\n--------------------------------------")
        print("Record ID:", event.get("RecordId"))
        print("Event ID:", event.get("EventId"))
        print("Account:", event.get("Account"))
        print("Domain:", event.get("Domain"))
        print("Logon Type:", event.get("LogonType"))
        print("Source IP:", event.get("SourceIP"))
        print("Workstation:", event.get("Workstation"))
        print("Time:", event.get("TimeCreated"))
