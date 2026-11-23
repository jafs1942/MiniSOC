
import subprocess
import json


def collect_sysmon_events(limit=20):
    ps_script = r"""
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = 1
    } -MaxEvents LIMIT |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $data = @{}

        foreach ($item in $xml.Event.EventData.Data) {
            $data[$item.Name] = $item.'#text'
        }

        [PSCustomObject]@{
            EventId = $_.Id
            TimeCreated = $_.TimeCreated.ToString("o")
            Data = $data
        }
    } | ConvertTo-Json -Depth 5
    """.replace("LIMIT", str(limit))

    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            print("Error:", result.stderr)
            return []

        if not result.stdout.strip():
            return []

        events = json.loads(result.stdout)

        if isinstance(events, dict):
            events = [events]

        return events

    except Exception as error:
        print("Collection failed:", error)
        return []


if __name__ == "__main__":
    print("\n========== MINISOC STRUCTURED COLLECTOR ==========")

    events = collect_sysmon_events()

    print("Total events collected:", len(events))

    for event in events:
        data = event.get("Data", {})

        print("\n----------------------------------")
        print("Event ID:", event.get("EventId"))
        print("Time:", event.get("TimeCreated"))
        print("Process:", data.get("Image"))
        print("PID:", data.get("ProcessId"))
        print("Command:", data.get("CommandLine"))
        print("Parent:", data.get("ParentImage"))
        print("User:", data.get("User"))
