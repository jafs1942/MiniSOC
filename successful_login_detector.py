
from datetime import datetime, timedelta
import ipaddress
import re

from security_collector import (
    collect_successful_logins,
    collect_failed_logins
)
from login_detector import parse_event_time, THRESHOLD, TIME_WINDOW_MINUTES



def is_external_ip(value):
    """Return True only for globally routable, non-multicast IPs."""

    if not value or not isinstance(value, str):
        return False

    try:
        address = ipaddress.ip_address(value.strip())

        return (
            address.is_global
            and not address.is_multicast
        )

    except ValueError:
        return False


def detect_remote_interactive_logins(events):
    alerts = []

    for event in events:
        if str(event.get("LogonType", "")) != "10":
            continue

        alerts.append({
            "severity": "MEDIUM",
            "rule": "Remote Interactive Login",
            "process": event.get("ProcessName") or "Unknown",
            "command": (
                f"Account: {event.get('Domain')}\\{event.get('Account')}; "
                f"Source IP: {event.get('SourceIP')}; "
                f"Workstation: {event.get('Workstation')}; "
                f"Logon Type: 10 (Remote Interactive)"
            )
        })

    return alerts


def detect_external_network_logins(events):
    alerts = []

    for event in events:
        if str(event.get("LogonType", "")) != "3":
            continue

        source_ip = str(event.get("SourceIP") or "").strip()

        if not is_external_ip(source_ip):
            continue

        alerts.append({
            "severity": "MEDIUM",
            "rule": "Unusual Network Login",
            "process": event.get("ProcessName") or "Unknown",
            "command": (
                f"Account: {event.get('Domain')}\\{event.get('Account')}; "
                f"Source IP: {source_ip}; "
                f"Workstation: {event.get('Workstation')}; "
                f"Logon Type: 3 (Network)"
            )
        })

    return alerts


def detect_success_after_brute_force(success_events, failed_events):
    alerts = []
    alerted_correlations = set()

    failures_by_source_account = {}

    for event in failed_events:
        source_ip = str(event.get("SourceIP") or "").strip()
        account = str(event.get("Account") or "").strip().lower()
        event_time = parse_event_time(event.get("TimeCreated"))

        if not source_ip or source_ip == "-" or not account or event_time is None:
            continue

        key = (source_ip, account)
        failures_by_source_account.setdefault(key, []).append(event_time)

    for event in success_events:
        source_ip = str(event.get("SourceIP") or "").strip()
        account = str(event.get("Account") or "").strip().lower()
        success_time = parse_event_time(event.get("TimeCreated"))

        if not source_ip or source_ip == "-" or not account or success_time is None:
            continue

        key = (source_ip, account)
        matching_failures = failures_by_source_account.get(key, [])

        window_start = success_time - timedelta(minutes=TIME_WINDOW_MINUTES)

        recent_failures = [
            failure_time
            for failure_time in matching_failures
            if window_start <= failure_time <= success_time
        ]

        if len(recent_failures) >= THRESHOLD:
            correlation_key = (
                source_ip,
                account,
                tuple(sorted(recent_failures))
            )

            if correlation_key in alerted_correlations:
                continue

            alerted_correlations.add(correlation_key)

            alerts.append({
                "severity": "HIGH",
                "rule": "Successful Login After Brute Force",
                "process": event.get("ProcessName") or "Unknown",
                "command": (
                    f"Account: {event.get('Domain')}\\{event.get('Account')}; "
                    f"Source IP: {source_ip}; "
                    f"{len(recent_failures)} failed attempts followed by "
                    f"a successful login within {TIME_WINDOW_MINUTES} minutes."
                )
            })

    return alerts

if __name__ == "__main__":
    print("\n======================================")
    print("   MINISOC SUCCESSFUL LOGIN DETECTOR")
    print("======================================")

    print("\nCollecting successful logins...")
    successful_events = collect_successful_logins(limit=200)

    print("Successful events collected:", len(successful_events))

    print("\nCollecting failed logins...")
    failed_events = collect_failed_logins(limit=200)

    print("Failed events collected:", len(failed_events))

    alerts = []

    alerts.extend(
        detect_remote_interactive_logins(successful_events)
    )

    alerts.extend(
        detect_external_network_logins(successful_events)
    )

    alerts.extend(
        detect_success_after_brute_force(
            successful_events,
            failed_events
        )
    )

    print("\nDetection results:")
    print("Alerts generated:", len(alerts))

    for number, alert in enumerate(alerts, start=1):
        print(f"\nALERT #{number}")
        print("Severity:", alert["severity"])
        print("Rule:", alert["rule"])
        print("Process:", alert["process"])
        print("Details:", alert["command"])

    print("\nAnalysis completed.")
    print("No alerts have been saved to the database.")
