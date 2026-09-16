# dummy_logs.py

# Linux ke sample logs
linux_sample_logs = """
Mar 16 10:00:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.105 port 45212 ssh2
Mar 16 10:00:05 server sshd[1235]: Failed password for invalid user admin from 192.168.1.105 port 45214 ssh2
Mar 16 10:00:10 server sshd[1236]: Failed password for invalid user admin from 192.168.1.105 port 45216 ssh2
Mar 16 10:00:15 server sshd[1237]: Failed password for invalid user admin from 192.168.1.105 port 45218 ssh2
Mar 16 10:00:20 server sshd[1238]: Failed password for invalid user admin from 192.168.1.105 port 45220 ssh2
Mar 16 10:01:00 server sshd[1240]: Accepted password for root from 192.168.1.105 port 45222 ssh2
Mar 16 10:05:00 server sshd[1245]: Accepted password for developer from 10.0.0.15 port 51234 ssh2
"""

# Windows ke sample logs
windows_sample_logs = [
    {"TimeCreated": "2026-03-16 10:00:02", "EventID": 4625, "TargetUserName": "admin", "IpAddress": "172.16.0.40"},
    {"TimeCreated": "2026-03-16 10:00:08", "EventID": 4625, "TargetUserName": "admin", "IpAddress": "172.16.0.40"},
    {"TimeCreated": "2026-03-16 10:00:14", "EventID": 4625, "TargetUserName": "admin", "IpAddress": "172.16.0.40"},
    {"TimeCreated": "2026-03-16 10:00:19", "EventID": 4625, "TargetUserName": "admin", "IpAddress": "172.16.0.40"},
    {"TimeCreated": "2026-03-16 10:00:25", "EventID": 4625, "TargetUserName": "admin", "IpAddress": "172.16.0.40"},
    {"TimeCreated": "2026-03-16 10:02:00", "EventID": 4624, "TargetUserName": "john_doe", "IpAddress": "172.16.0.40"}
]

# Linux file create karega
with open("linux_auth.log", "w") as f:
    f.write(linux_sample_logs.strip())

# Windows file create karega
import json
with open("windows_events.json", "w") as f:
    json.dump(windows_sample_logs, f, indent=4)

print("SUCCESS: Dono sample files ban gayi hain!")