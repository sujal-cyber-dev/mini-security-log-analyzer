# analyzer.py
import re
import json
from collections import defaultdict

def parse_linux_content(file_content):
    unified_events = []
    
    # 1. Standard SSH Syslog
    ssh_pattern = re.compile(
        r"^(?P<date>\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]:\s+(?P<status>Failed|Accepted)\s+password\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
        re.IGNORECASE
    )
    
    # 2. Universal Enterprise / Activity Pattern
    app_pattern = re.compile(
        r"^(?P<date>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<level>\w+)\s+(?:User\s+)?(?P<actor>\S+)?\s*(?P<msg>.*?)(?:\s+(?:from|on)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3}))?$",
        re.IGNORECASE
    )

    for raw_line in file_content.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Check SSH Syslog
        m_ssh = ssh_pattern.search(line)
        if m_ssh:
            d = m_ssh.groupdict()
            status = d["status"].lower()
            unified_events.append({
                "timestamp": f"2026 {d['date']}",
                "os_source": "Linux Syslog",
                "category": "AUTHENTICATION",
                "event_type": "LOGIN_SUCCESS" if status == "accepted" else "LOGIN_FAILED",
                "user": d["user"],
                "ip": d["ip"],
                "details": f"SSH password authentication {status}."
            })
            continue

        # Check Enterprise Logs
        m_app = app_pattern.search(line)
        if m_app:
            d = m_app.groupdict()
            msg = (d["msg"] or "").lower()
            user = d["actor"] if d["actor"] else "System"
            ip = d["ip"] if d["ip"] else "Localhost"
            level = (d["level"] or "INFO").upper()

            # Intelligent Categorization Engine
            if "malware detected" in msg:
                category, ev_type = "MALWARE", "MALWARE_ALERT"
            elif "quarantined" in msg:
                category, ev_type = "MALWARE", "MALWARE_REMEDIATED"
            elif any(k in msg for k in ["failed login", "login failed"]):
                category, ev_type = "AUTHENTICATION", "LOGIN_FAILED"
            elif any(k in msg for k in ["logged in successfully", "login success"]):
                category, ev_type = "AUTHENTICATION", "LOGIN_SUCCESS"
            elif any(k in msg for k in ["unauthorized", "restricted folder"]):
                category, ev_type = "ACCESS_CONTROL", "UNAUTHORIZED_ACCESS"
            elif any(k in msg for k in ["firewall rules", "file permissions", "deleted user", "modified user"]):
                category, ev_type = "PRIVILEGE_TAMPERING", "CONFIG_CHANGE"
            elif any(k in msg for k in ["connection lost", "backup failed", "synchronization failed"]):
                category, ev_type = "SYSTEM_FAILURE", "SYSTEM_ERROR"
            elif any(k in msg for k in ["downloaded", "uploaded", "viewed report", "opened document", "opened file"]):
                category, ev_type = "DATA_ACCESS", "FILE_ACTIVITY"
            else:
                category, ev_type = "AUDIT", "GENERAL_LOG"

            unified_events.append({
                "timestamp": d["date"],
                "os_source": "Enterprise Telemetry",
                "category": category,
                "event_type": ev_type,
                "user": user,
                "ip": ip,
                "details": d["msg"]
            })

    return unified_events

def parse_windows_content(file_content):
    unified_events = []
    try:
        events = json.loads(file_content)
        for ev in events:
            eid = ev.get("EventID")
            user = ev.get("TargetUserName", "Unknown")
            ip = ev.get("IpAddress", "Unknown")
            time = ev.get("TimeCreated", "Unknown")

            # Windows Security Event Mapping
            if eid == 4624:
                category, ev_type = "AUTHENTICATION", "LOGIN_SUCCESS"
                desc = "Successful logon"
            elif eid == 4625:
                category, ev_type = "AUTHENTICATION", "LOGIN_FAILED"
                desc = "Failed logon attempt"
            elif eid in [4720, 4726, 4738]:
                category, ev_type = "PRIVILEGE_TAMPERING", "ACCOUNT_MANAGEMENT"
                desc = f"Account lifecycle event (ID {eid})"
            elif eid == 7045:
                category, ev_type = "PERSISTENCE", "SERVICE_INSTALLED"
                desc = "New system service created"
            elif eid == 1102:
                category, ev_type = "DEFENSE_EVASION", "AUDIT_LOG_CLEARED"
                desc = "Security audit log was manually cleared"
            else:
                category, ev_type = "AUDIT", f"EVENT_{eid}"
                desc = f"Windows Event ID {eid}"

            unified_events.append({
                "timestamp": time,
                "os_source": "Windows Event Log",
                "category": category,
                "event_type": ev_type,
                "user": user,
                "ip": ip,
                "details": desc
            })
    except Exception:
        pass
    return unified_events

def analyze_events(all_events):
    if not all_events:
        return []

    incidents = []
    
    # 1. Immediate Threat Rules (Global & Critical Indicators)
    for ev in all_events:
        if ev["event_type"] == "MALWARE_ALERT":
            incidents.append({
                "source_ip": ev["ip"],
                "incident_type": "Active Malware Execution",
                "risk_level": "CRITICAL",
                "evidence": f"Malware detected on endpoint: {ev['details']}",
                "reason": "Host security breached. Endpoint protection alert triggered.",
                "timeline": [ev]
            })
        elif ev["event_type"] == "AUDIT_LOG_CLEARED":
            incidents.append({
                "source_ip": ev["ip"],
                "incident_type": "Defense Evasion (Anti-Forensics)",
                "risk_level": "CRITICAL",
                "evidence": "Windows Security Event Log was wiped (Event ID 1102).",
                "reason": "Adversary attempting to conceal malicious footprints.",
                "timeline": [ev]
            })
        elif ev["event_type"] == "UNAUTHORIZED_ACCESS":
            incidents.append({
                "source_ip": ev["ip"],
                "incident_type": "Access Violation",
                "risk_level": "HIGH",
                "evidence": f"Unauthorized resource access attempt: {ev['details']}",
                "reason": f"Account '{ev['user']}' attempted to access restricted asset.",
                "timeline": [ev]
            })
        elif ev["event_type"] == "CONFIG_CHANGE":
            incidents.append({
                "source_ip": ev["ip"],
                "incident_type": "Privilege / Security Tampering",
                "risk_level": "HIGH",
                "evidence": f"Critical modification: {ev['details']}",
                "reason": f"User '{ev['user']}' altered core system policies or accounts.",
                "timeline": [ev]
            })
        elif ev["event_type"] == "SYSTEM_ERROR":
            incidents.append({
                "source_ip": ev["ip"],
                "incident_type": "System Outage / Failure",
                "risk_level": "MEDIUM",
                "evidence": f"System fault reported: {ev['details']}",
                "reason": "System infrastructure or backup synchronization disruption.",
                "timeline": [ev]
            })

    # 2. Correlation Engine for Authentication & Brute-Force (Grouped by IP)
    ip_activity = defaultdict(list)
    for ev in all_events:
        if ev["category"] == "AUTHENTICATION":
            ip_activity[ev["ip"]].append(ev)

    for ip, events in ip_activity.items():
        failed = [e for e in events if e["event_type"] == "LOGIN_FAILED"]
        success = [e for e in events if e["event_type"] == "LOGIN_SUCCESS"]
        users = list(set(e["user"] for e in events))

        if len(failed) >= 3 and len(success) > 0:
            incidents.append({
                "source_ip": ip,
                "incident_type": "Brute-Force & Credential Breach",
                "risk_level": "CRITICAL",
                "evidence": f"{len(failed)} failed logins followed by authentication SUCCESS.",
                "reason": f"Credential stuffing or guessing compromise targeting {', '.join(users)}.",
                "timeline": events
            })
        elif len(failed) >= 2:
            incidents.append({
                "source_ip": ip,
                "incident_type": "Brute-Force Activity",
                "risk_level": "HIGH",
                "evidence": f"{len(failed)} consecutive failed logins.",
                "reason": f"Repeated unauthorized authentication attempts against {', '.join(users)}.",
                "timeline": events
            })
        elif len(success) > 0 and len(failed) == 0:
            incidents.append({
                "source_ip": ip,
                "incident_type": "Normal Authentication",
                "risk_level": "LOW",
                "evidence": f"{len(success)} authorized login session(s).",
                "reason": f"Verified regular logins by user(s): {', '.join(users)}.",
                "timeline": events
            })

    # Sort so CRITICAL alerts appear first
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    incidents.sort(key=lambda x: order.get(x["risk_level"], 4))
    return incidents