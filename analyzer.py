# analyzer.py
from parser import parse_linux_logs, parse_windows_logs
from collections import defaultdict
import json

def run_security_analysis():
    # Step 1 se parse kiye huye logs read karein
    linux_events = parse_linux_logs("linux_auth.log")
    windows_events = parse_windows_logs("windows_events.json")
    all_events = linux_events + windows_events

    # IP ke basis par events group karo
    ip_activity = defaultdict(list)
    for event in all_events:
        ip_activity[event["ip"]].append(event)

    incidents = []

    # Correlation logic
    for ip, events in ip_activity.items():
        failed_attempts = [e for e in events if e["event_type"] == "LOGIN_FAILED"]
        success_attempts = [e for e in events if e["event_type"] == "LOGIN_SUCCESS"]

        targeted_users = list(set(e["user"] for e in events))
        os_sources = list(set(e["os_source"] for e in events))

        # Scenario 1: Brute Force followed by Success (CRITICAL)
        if len(failed_attempts) >= 3 and len(success_attempts) > 0:
            incidents.append({
                "source_ip": ip,
                "incident_type": "Brute-Force & Potential Breach",
                "risk_level": "CRITICAL",
                "evidence": f"Total {len(failed_attempts)} failed login attempts followed by a SUCCESSFUL login.",
                "reason": f"An attacker likely guessed or cracked credentials on {', '.join(os_sources)} targeting user(s): {', '.join(targeted_users)}.",
                "total_events": len(events),
                "timeline": events
            })

        # Scenario 2: High number of Failed Logins only (HIGH RISK)
        elif len(failed_attempts) >= 3:
            incidents.append({
                "source_ip": ip,
                "incident_type": "Authentication Brute-Force",
                "risk_level": "HIGH",
                "evidence": f"{len(failed_attempts)} repeated failed login attempts observed.",
                "reason": f"Suspicious repeated login failures from this IP targeting {', '.join(targeted_users)} without success.",
                "total_events": len(events),
                "timeline": events
            })

        # Scenario 3: Normal Activity (LOW RISK / INFORMATIONAL)
        else:
            incidents.append({
                "source_ip": ip,
                "incident_type": "Normal User Activity",
                "risk_level": "LOW",
                "evidence": f"Single/Normal login activity recorded ({len(events)} event).",
                "reason": "No anomalous authentication patterns detected.",
                "total_events": len(events),
                "timeline": events
            })

    return incidents

if __name__ == "__main__":
    detected_incidents = run_security_analysis()
    print("================ SECURITY INCIDENTS DETECTED ================\n")
    for inc in detected_incidents:
        print(f"🚨 IP: {inc['source_ip']} | Risk: [{inc['risk_level']}]")
        print(f"   Incident: {inc['incident_type']}")
        print(f"   Evidence: {inc['evidence']}")
        print(f"   Reason:   {inc['reason']}")
        print("-" * 60)