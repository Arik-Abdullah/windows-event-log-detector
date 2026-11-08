"""Creates SYNTHETIC Windows Security events (documentation-range IPs, fictional hosts/users).

Writes events.csv in the same shape as the PowerShell export described in the README.
"""
import csv
from datetime import datetime, timedelta

base = datetime(2026, 11, 9, 1, 0, 0)
rows = []


def add(offset_s, event_id, computer="WS-FIN-01", user="", subject="", ip="", ltype=""):
    rows.append({
        "TimeCreated": (base + timedelta(seconds=offset_s)).strftime("%Y-%m-%dT%H:%M:%S.0000000+00:00"),
        "EventID": event_id, "Computer": computer, "TargetUserName": user,
        "SubjectUserName": subject, "IpAddress": ip, "LogonType": ltype,
    })


# normal activity
for i, u in enumerate(["aisha", "rahim", "nusrat", "tanvir"]):
    add(i * 600, 4624, user=u, ip="192.0.2.%d" % (20 + i), ltype="2")
add(1500, 4625, user="rahim", ip="192.0.2.21", ltype="2")  # one typo, benign

# RDP brute force against Administrator, then success (HIGH)
for i in range(12):
    add(1800 + i * 6, 4625, computer="SRV-RDP-01", user="Administrator", ip="203.0.113.45", ltype="3")
add(1900, 4624, computer="SRV-RDP-01", user="Administrator", ip="203.0.113.45", ltype="10")

# password spraying, no success (MEDIUM)
for i, u in enumerate(["admin", "backup", "sql", "test", "support", "guest", "svc_web"]):
    add(2400 + i * 15, 4625, computer="SRV-RDP-01", user=u, ip="198.51.100.7", ltype="3")

# lockout (MEDIUM)
add(2600, 4740, computer="DC-01", user="nusrat")

# new account added to Administrators (HIGH)
add(3000, 4720, computer="SRV-RDP-01", user="svc_backup2", subject="Administrator")
add(3180, 4732, computer="SRV-RDP-01", user="Administrators", subject="Administrator")

# log cleared (HIGH)
add(3300, 1102, computer="SRV-RDP-01", subject="Administrator")

rows.sort(key=lambda r: r["TimeCreated"])
with open("events.csv", "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(rows)
print(f"Wrote events.csv with {len(rows)} synthetic events")
