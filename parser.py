# parser.py
import re
import json

def parse_linux_logs(file_path):
    unified_events = []
    # Linux log se date, user, IP aur status nikalne ke liye
    pattern = r"^(?P<date>\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+(?P<status>Failed|Accepted)\s+password\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
    
    with open(file_path, "r") as f:
        for line in f:
            match = re.search(pattern, line)
            if match:
                data = match.groupdict()
                unified_events.append({
                    "timestamp": f"2026 {data['date']}",
                    "os_source": "Linux",
                    "event_type": "LOGIN_SUCCESS" if data["status"] == "Accepted" else "LOGIN_FAILED",
                    "user": data["user"],
                    "ip": data["ip"]
                })
    return unified_events

def parse_windows_logs(file_path):
    unified_events = []
    with open(file_path, "r") as f:
        events = json.load(f)
        for ev in events:
            unified_events.append({
                "timestamp": ev["TimeCreated"],
                "os_source": "Windows",
                # Event 4624 matlab Success, 4625 matlab Failed
                "event_type": "LOGIN_SUCCESS" if ev["EventID"] == 4624 else "LOGIN_FAILED",
                "user": ev["TargetUserName"],
                "ip": ev["IpAddress"]
            })
    return unified_events

if __name__ == "__main__":
    linux_data = parse_linux_logs("linux_auth.log")
    windows_data = parse_windows_logs("windows_events.json")
    
    # Dono OS ke logs ko ek jagah joda
    all_normalized_logs = linux_data + windows_data
    
    print(f"Total Logs Normalized: {len(all_normalized_logs)}")
    print("\nEk example normalized format ka:")
    print(json.dumps(all_normalized_logs[0], indent=2))