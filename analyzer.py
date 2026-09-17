# analyzer.py
import re
import json
from collections import defaultdict

def parse_linux_content(file_content):
    unified_events = []
    
    # 1. Standard SSH Syslog Pattern
    ssh_pattern = re.compile(
        r"^(?P<date>\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+(?P<status>Failed|Accepted)\s+password\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
        re.IGNORECASE
    )
    
    # 2. Flexible Enterprise App Pattern (matches John, Alice, Eve, Admin, etc.)
    app_pattern = re.compile(
        r"^(?P<date>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<level>\w+)\s+(?:User\s+)?(?P<user>\S+)\s+(?P<msg>.*?)\s+(?:from|on)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
        re.IGNORECASE
    )

    for raw_line in file_content.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Check standard Linux SSH
        m_ssh = ssh_pattern.search(line)
        if m_ssh:
            d = m_ssh.groupdict()
            unified_events.append({
                "timestamp": f"2026 {d['date']}",
                "os_source": "Linux Syslog",
                "event_type": "LOGIN_SUCCESS" if d["status"].lower() == "accepted" else "LOGIN_FAILED",
                "user": d["user"],
                "ip": d["ip"]
            })
            continue

        # Check Enterprise / Application format
        m_app = app_pattern.search(line)
        if m_app:
            d = m_app.groupdict()
            msg = d["msg"].lower()
            
            # Identify event nature
            if "failed login" in msg or "unauthorized" in msg or "restricted" in msg:
                ev_type = "LOGIN_FAILED"
            elif "logged in successfully" in msg or "login" in msg:
                ev_type = "LOGIN_SUCCESS"
            else:
                # Normal informational activities
                ev_type = "ACTIVITY"

            unified_events.append({
                "timestamp": d["date"],
                "os_source": "Enterprise App",
                "event_type": ev_type,
                "user": d["user"],
                "ip": d["ip"]
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
        targeted_users = list(set(e["user"] for e in events if e["user"] != "System"))
        os_sources = list(set(e["os_source"] for e in events))
        user_str = ", ".join(targeted_users) if targeted_users else "Unknown"

        # Threat Rules
        if len(failed_attempts) >= 3 and len(success_attempts) > 0:
            incidents.append({
                "source_ip": ip,
                "incident_type": "Brute-Force & Breach",
                "risk_level": "CRITICAL",
                "evidence": f"{len(failed_attempts)} failed/suspicious events followed by login.",
                "reason": f"Breach detected targeting account(s): {user_str}.",
                "total_events": len(events),
                "timeline": events
            })
        elif len(failed_attempts) >= 2:
            incidents.append({
                "source_ip": ip,
                "incident_type": "Brute-Force Activity",
                "risk_level": "HIGH",
                "evidence": f"{len(failed_attempts)} failed authentication attempts.",
                "reason": f"Repeated unauthorized attempts against {user_str}.",
                "total_events": len(events),
                "timeline": events
            })
        else:
            incidents.append({
                "source_ip": ip,
                "incident_type": "Benign / Normal Activity",
                "risk_level": "LOW",
                "evidence": f"{len(events)} standard operation(s) logged.",
                "reason": f"Regular activity by {user_str}.",
                "total_events": len(events),
                "timeline": events
            })

    return incidents