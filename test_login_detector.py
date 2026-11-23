
from login_detector import detect_brute_force

test_events = [
    {
        "SourceIP": "192.168.0.206",
        "Account": "testuser",
        "TimeCreated": "2026-11-20T15:00:00+01:00"
    },
    {
        "SourceIP": "192.168.0.206",
        "Account": "testuser",
        "TimeCreated": "2026-11-20T15:01:00+01:00"
    },
    {
        "SourceIP": "192.168.0.206",
        "Account": "testuser",
        "TimeCreated": "2026-11-20T15:02:00+01:00"
    }
]

print("\n===== MINISOC DETECTION TEST =====")

alerts = detect_brute_force(test_events)

print("Test events:", len(test_events))
print("Alerts generated:", len(alerts))

for alert in alerts:
    print("\nSEVERITY:", alert["severity"])
    print("RULE:", alert["rule"])
    print("SOURCE:", alert["process"])
    print("DETAILS:", alert["command"])

if alerts:
    print("\nSUCCESS: Brute-force detection works!")
else:
    print("\nFAILED: Detection did not trigger.")
