# analyzer.py
import re
import json
from collections import defaultdict

def parse_linux_content(file_content):
    unified_events = []
    pattern = r"^(?P<date>\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+(?P<status>Failed|Accepted)\s+password\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
    
    for line in file_content.splitlines():
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