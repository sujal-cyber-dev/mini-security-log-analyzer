# app.py
import streamlit as st
import pandas as pd
from analyzer import parse_linux_content, parse_windows_content, analyze_events

st.set_page_config(page_title="Security Log Analyzer", layout="wide")

st.title("🛡️ Cross-Platform Security Log Analyzer & Incident Triage")
st.markdown("Upload raw **Linux auth.log** or **Windows JSON Event Logs** to detect brute-force attacks and security anomalies.")

# Sidebar File Upload Section
st.sidebar.header("📁 Upload Telemetry Logs")
uploaded_linux = st.sidebar.file_uploader("Upload Linux Log (.log, .txt)", type=["log", "txt"])
uploaded_windows = st.sidebar.file_uploader("Upload Windows Events (.json)", type=["json"])

all_events = []

# Process Linux upload
if uploaded_linux is not None:
    linux_text = uploaded_linux.read().decode("utf-8")
    all_events.extend(parse_linux_content(linux_text))

# Process Windows upload
if uploaded_windows is not None:
    windows_text = uploaded_windows.read().decode("utf-8")
    all_events.extend(parse_windows_content(windows_text))

# Fallback: Agar user ne koi file upload nahi ki toh dummy logs dikhao
if not uploaded_linux and not uploaded_windows:
    st.sidebar.info("💡 No files uploaded yet. Showing built-in demo sample data.")
    try:
        with open("linux_auth.log", "r") as f:
            all_events.extend(parse_linux_content(f.read()))
        with open("windows_events.json", "r") as f:
            all_events.extend(parse_windows_content(f.read()))
    except Exception:
        pass

incidents = analyze_events(all_events)

if incidents:
    # Metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Monitored IPs", len(incidents))
    col2.metric("Critical Alerts", sum(1 for i in incidents if i["risk_level"] == "CRITICAL"))
    col3.metric("High Alerts", sum(1 for i in incidents if i["risk_level"] == "HIGH"))
    col4.metric("Low Alerts", sum(1 for i in incidents if i["risk_level"] == "LOW"))

    st.markdown("---")

    # Incidents Table
    st.subheader("🚨 Detected Incidents & Rationales")
    summary_data = [{
        "Source IP": inc["source_ip"],
        "Risk Level": inc["risk_level"],
        "Incident Type": inc["incident_type"],
        "Evidence": inc["evidence"],
        "Reason": inc["reason"]
    } for inc in incidents]

    st.dataframe(pd.DataFrame(summary_data), use_container_width=True)

    st.markdown("---")

    # Timeline View
    st.subheader("🔍 Forensic Timeline Investigation")
    selected_ip = st.selectbox("Select IP to Investigate:", [inc["source_ip"] for inc in incidents])
    selected_incident = next(i for i in incidents if i["source_ip"] == selected_ip)

    st.write(f"**Threat Assessment:** `{selected_incident['risk_level']}`")
    st.info(f"**Analyst Note:** {selected_incident['reason']}")

    timeline_df = pd.DataFrame(selected_incident["timeline"])
    st.table(timeline_df[["timestamp", "os_source", "event_type", "user"]])
else:
    st.warning("No events found in the uploaded file(s).")