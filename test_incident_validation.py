from incident_manager import (
    create_incident,
    update_incident_status,
    add_investigation_note,
    link_alert_to_incident
)

tests = [
    (
        "INVALID SEVERITY",
        lambda: create_incident(
            "Invalid Test",
            "Testing invalid severity",
            "CRITICAL"
        )
    ),
    (
        "INVALID STATUS",
        lambda: update_incident_status(1, "PENDING")
    ),
    (
        "MISSING INCIDENT",
        lambda: add_investigation_note(
            9999, "SOC Analyst", "Test note"
        )
    ),
    (
        "MISSING ALERT",
        lambda: link_alert_to_incident(1, 9999)
    )
]

for name, test in tests:
    try:
        test()
        print(name + ": FAIL - invalid input accepted")

    except Exception as error:
        print(name + ": PASS -", error)