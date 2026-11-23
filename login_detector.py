
from collections import defaultdict
from datetime import timedelta
import re

from security_collector import collect_failed_logins
from alert_store import initialize_database, save_alerts


THRESHOLD = 3
TIME_WINDOW_MINUTES = 10


def parse_event_time(timestamp):
    """Normalize Windows timestamps for Python 3.10."""
    if not timestamp:
        return None

    timestamp = re.sub(r"(\.\d{6})\d+", r"\1", timestamp)

    try:
        from datetime import datetime
        return datetime.fromisoformat(timestamp)
    except (ValueError, TypeError):
        return None


def detect_brute_force(events):
    """
    Detect:
    1. Repeated failed logins against one account.
    2. Password spraying against multiple accounts.

    Both detections are grouped by source IP and use a
    configurable threshold and time window.
    """

    grouped = defaultdict(list)

    for event in events:
        source_ip = str(event.get("SourceIP") or "").strip()
        account = str(event.get("Account") or "").strip()
        event_time = parse_event_time(event.get("TimeCreated"))

        if not source_ip or source_ip == "-" or not account:
            continue

        if event_time is None:
            continue

        grouped[source_ip].append({
            "account": account,
            "time": event_time
        })

    alerts = []

    for source_ip, attempts in grouped.items():
        attempts.sort(key=lambda item: item["time"])

        # DETECTION 1: BRUTE FORCE AGAINST ONE ACCOUNT
        accounts = defaultdict(list)

        for attempt in attempts:
            accounts[attempt["account"].lower()].append(attempt)

        for account, account_attempts in accounts.items():
            for index, current in enumerate(account_attempts):
                window_start = current["time"] - timedelta(
                    minutes=TIME_WINDOW_MINUTES
                )

                matching = [
                    item for item in account_attempts
                    if window_start <= item["time"] <= current["time"]
                ]

                if len(matching) >= THRESHOLD:
                    alerts.append({
                        "severity": "HIGH",
                        "rule": "Brute Force Attack - Single Account",
                        "process": f"Source IP: {source_ip}",
                        "command": (
                            f"{len(matching)} failed login attempts "
                            f"against account {current['account']} "
                            f"within {TIME_WINDOW_MINUTES} minutes."
                        )
                    })
                    break

        # DETECTION 2: PASSWORD SPRAYING
        for current in attempts:
            window_start = current["time"] - timedelta(
                minutes=TIME_WINDOW_MINUTES
            )

            matching = [
                item for item in attempts
                if window_start <= item["time"] <= current["time"]
            ]

            targeted_accounts = {
                item["account"].lower()
                for item in matching
            }

            if len(targeted_accounts) >= THRESHOLD:
                account_names = sorted({
                    item["account"] for item in matching
                })

                alerts.append({
                    "severity": "HIGH",
                    "rule": "Password Spraying Attack",
                    "process": f"Source IP: {source_ip}",
                    "command": (
                        f"{len(targeted_accounts)} distinct accounts "
                        f"targeted within {TIME_WINDOW_MINUTES} minutes. "
                        f"Target accounts: {', '.join(account_names)}"
                    )
                })
                break

    return alerts


if __name__ == "__main__":
    print("\n======================================")
    print("       MINISOC LOGIN DETECTOR")
    print("======================================")

    initialize_database()

    print("\nCollecting failed login events...")

    events = collect_failed_logins(limit=100)

    print("Events collected:", len(events))

    alerts = detect_brute_force(events)

    print("Detection alerts generated:", len(alerts))

    for alert in alerts:
        print("\nSeverity:", alert["severity"])
        print("Detection:", alert["rule"])
        print("Source:", alert["process"])
        print("Details:", alert["command"])

    if alerts:
        save_alerts(alerts)

    print("\nMINISOC LOGIN ANALYSIS COMPLETED")
