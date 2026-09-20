# agent.py - Enterprise SIEM Endpoint Agent (Like Wazuh / Splunk Forwarder)
import time
import socket
import platform
import getpass
import psutil
import datetime
import random

LOG_FILE = "live_stream.log"

def ship_telemetry(log_entry):
    """SIEM collector file me safely telemetry append karna."""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_entry + "\n")

def get_timestamp():
    return datetime.datetime.now().strftime("%b %d %H:%M:%S")

def run_agent():
    hostname = socket.gethostname()
    os_name = platform.system()
    current_user = getpass.getuser()

    print("================================================================")
    print("🛡️  MINI-SIEM ENDPOINT TELEMETRY AGENT (Wazuh/Splunk Architecture)")
    print("   Developed & Engineered by: Sujal")
    print(f"🖥️  Endpoint Hostname : {hostname}")
    print(f"💻 OS Platform       : {os_name} {platform.release()}")
    print(f"👤 Monitored User    : {current_user}")
    print(f"📡 Pipeline Target   : {LOG_FILE}")
    print("================================================================")
    print("Mode: Continuously shipping live endpoint telemetry to SIEM...")
    print("Press [Ctrl + C] to stop the agent.\n")

    # 1. Agent Registration Event
    startup_log = f"{get_timestamp()} {hostname} siem_core[sujal_agent_v1]: AGENT_START Endpoint agent initialized for user '{current_user}'"
    ship_telemetry(startup_log)
    print(f"[SHIPPED] Initial registration sent.")

    event_counter = 1

    while True:
        try:
            # Real Endpoint Telemetry Collect Karna
            cpu_usage = psutil.cpu_percent(interval=1)
            mem_info = psutil.virtual_memory().percent
            
            # Active network connection fetch karna
            connections = [c for c in psutil.net_connections(kind='inet') if c.status == 'ESTABLISHED']
            active_conn_count = len(connections)

            # Standard Telemetry Heartbeat
            telemetry_log = (
                f"{get_timestamp()} {hostname} siem_core[sujal_agent_v1]: "
                f"HEALTH_OK User='{current_user}' CPU={cpu_usage}% RAM={mem_info}% ActiveSockets={active_conn_count}"
            )
            ship_telemetry(telemetry_log)
            print(f"[SHIPPED #{event_counter}] System Telemetry (CPU: {cpu_usage}%, RAM: {mem_info}%, Connections: {active_conn_count})")

            # Har 4 cycles ke baad ek realistic security event forward karna (Demo purpose ke liye)
            # Attack burst simulation with fixed attacker IP
            if event_counter % 3 == 0:
                demo_attack = (
                    f"{get_timestamp()} {hostname} sshd[8842]: "
                    f"Failed password for invalid user admin from 192.168.1.199 port 22 ssh2"
                )
                ship_telemetry(demo_attack)
                print(f"⚠️  [SECURITY EVENT SHIPPED] Simulated Attack from 192.168.1.199")

            event_counter += 1
            time.sleep(3)

        except KeyboardInterrupt:
            shutdown_log = f"{get_timestamp()} {hostname} siem_agent[01]: AGENT_STOP Endpoint agent graceful shutdown"
            ship_telemetry(shutdown_log)
            print("\n🛑 Agent stopped by administrator.")
            break
        except Exception as e:
            time.sleep(3)

if __name__ == "__main__":
    run_agent()