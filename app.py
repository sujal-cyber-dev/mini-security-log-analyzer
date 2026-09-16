# app.py
import streamlit as st
import pandas as pd
from analyzer import run_security_analysis

# Page Config
st.set_page_config(page_title="Mini Security Log Analyzer", layout="wide")

st.title("🛡️ Cross-Platform Security Log Analyzer & Incident Triage")
st.markdown("Automated ingestion, normalization, and explainable threat detection for **Windows** & **Linux** telemetry.")

# Run Detection
incidents = run_security_analysis()

# Top Metrics Bar
col1, col2, col3, col4 = st.columns(4)
total_ips = len(incidents)
critical_count = sum(1 for i in incidents if i["risk_level"] == "CRITICAL")
high_count = sum(1 for i in incidents if i["risk_level"] == "HIGH")
low_count = sum(1 for i in incidents if i["risk_level"] == "LOW")

col1.metric("Unique IPs Monitored", total_ips)
col2.metric("Critical Alerts", critical_count)
col3.metric("High Alerts", high_count)
col4.metric("Benign/Low", low_count)

st.markdown("---")

# Main Section: Incidents Overview
st.subheader("🚨 Detected Incidents & Explainable Evidence")

# Incidents ki summary table
summary_data = []
for inc in incidents:
    summary_data.append({
        "Source IP": inc["source_ip"],
        "Risk Level": inc["risk_level"],
        "Incident Type": inc["incident_type"],
        "Evidence": inc["evidence"],
        "Reason": inc["reason"]
    })

df_summary = pd.DataFrame(summary_data)
st.dataframe(df_summary, use_container_width=True)

st.markdown("---")

# Forensic Investigation / Timeline Section
st.subheader("🔍 Forensic Timeline Investigation")
selected_ip = st.selectbox("Investigate Specific IP Address:", [inc["source_ip"] for inc in incidents])

selected_incident = next(i for i in incidents if i["source_ip"] == selected_ip)

st.write(f"**Threat Assessment for {selected_ip}:** `{selected_incident['risk_level']}`")
st.info(f"**Analyst Note:** {selected_incident['reason']}")

# Show raw timeline events for this IP
timeline_df = pd.DataFrame(selected_incident["timeline"])
st.write("Chronological Event Sequence:")
st.table(timeline_df[["timestamp", "os_source", "event_type", "user"]])