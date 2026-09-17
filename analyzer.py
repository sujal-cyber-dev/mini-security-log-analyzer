# analyzer.py
import re
import json
from collections import defaultdict

def parse_linux_content(file_content):
    unified_events = []
    
    # Pattern 1: Standard Linux SSH Syslog
    ssh_pattern = r"^(?P<date>\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+(?P<status>Failed|Accepted)\s+password\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
    
    # Pattern 2: Enterprise / Application Activity Log (Teacher's Format)
    app_pattern = r"^(?P<date>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\w+\s+User\s+(?P<user>\S+)\s+(?P<action>logged in successfully|failed login attempt)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"

    for line in file_content.splitlines():
        # Check SSH format
        ssh_match = re.search(ssh_pattern, line)
        if ssh_match:
            data = ssh_match.groupdict()
            unified_events.append({
                "timestamp": f"2026 {data['date']}",
                "os_source": "Linux",
                "event_type": "LOGIN_SUCCESS" if data["status"] == "Accepted" else "LOGIN_FAILED",
                "user": data["user"],
                "ip": data["ip"]
            })
            continue

        # Check Enterprise Application format
        app_match = re.search(app_pattern, line)
        if app_match:
            data = app_match.groupdict()
            unified_events.append({
                "timestamp": data["date"],
                "os_source": "Enterprise App",
                "event_type": "LOGIN_SUCCESS" if "successfully" in data["action"] else "LOGIN_FAILED",
                "user": data["user"],
                "ip": data["ip"]
            })

    return unified_events

def parse_windows_content(file_content):
    unified_events = []
    try:
        events = json.loads(file_content)
        for ev in events:
            unified_events.append({
                "timestamp": ev.get("TimeCreated", "Unknown"),
                "os_source": "Windows",
                "event_type": "LOGIN_SUCCESS" if ev.get("EventID") == 4624 else "LOGIN_FAILED",
                "user": ev.get("TargetUserName", "Unknown"),
                "ip": ev.get("IpAddress", "Unknown")
            })
    except Exception:
        pass
    return unified_events

def analyze_events(all_events):
    if not all_events:
        return []

    ip_activity = defaultdict(list)
    for event in all_events:
        ip_activity[event["ip"]].append(event)

    incidents = []

    for ip, events in ip_activity.items():
        failed_attempts = [e for e in events if e["event_type"] == "LOGIN_FAILED"]
        success_attempts = [e for e in events if e["event_type"] == "LOGIN_SUCCESS"]
        targeted_users = list(set(e["user"] for e in events))
        os_sources = list(set(e["os_source"] for e in events))

        if len(failed_attempts) >= 3 and len(success_attempts) > 0:
            incidents.append({
                "source_ip": ip,
                "incident_type": "Brute-Force & Potential Breach",
                "risk_level": "CRITICAL",
                "evidence": f"Total {len(failed_attempts)} failed login attempts followed by a SUCCESSFUL login.",
                "reason": f"Suspected breach on {', '.join(os_sources)} targeting user(s): {', '.join(targeted_users)}.",
                "total_events": len(events),
                "timeline": events
            })
        elif len(failed_attempts) >= 3:
            incidents.append({
                "source_ip": ip,
                "incident_type": "Authentication Brute-Force",
                "risk_level": "HIGH",
                "evidence": f"{len(failed_attempts)} repeated failed login attempts observed.",
                "reason": f"Suspicious repeated login failures targeting {', '.join(targeted_users)} without success.",
                "total_events": len(events),
                "timeline": events
            })
        else:
            incidents.append({
                "source_ip": ip,
                "incident_type": "Normal User Activity",
                "risk_level": "LOW",
                "evidence": f"Normal authentication pattern ({len(events)} event(s)).",
                "reason": "No malicious indicators detected.",
                "total_events": len(events),
                "timeline": events
            })

    return incidents