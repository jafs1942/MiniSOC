
from alert_store import get_alerts

print("\n======================================")
print("       MINISOC ALERT HISTORY")
print("======================================")

alerts = get_alerts()

if not alerts:
    print("\nNo saved alerts found.")

else:
    print(f"\nTotal saved alerts: {len(alerts)}")

    for alert in alerts:
        print("\n--------------------------------------")
        print("Alert ID:", alert[0])
        print("Severity:", alert[1])
        print("Detection:", alert[2])
        print("Process:", alert[3])
        print("Detected At:", alert[4])

print("\n======================================")
print("       END OF ALERT HISTORY")
print("======================================")
