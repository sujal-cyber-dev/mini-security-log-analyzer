# app.py
import streamlit as st
import pandas as pd
from fpdf import FPDF
from datetime import datetime
from analyzer import parse_linux_content, parse_windows_content, analyze_events

st.set_page_config(page_title="Security Log Analyzer & SIEM", layout="wide")

st.title("🛡️ Cross-Platform Security Log Analyzer & Incident Triage")
st.markdown("Automated ingestion, normalization, explainable threat detection, and forensic reporting.")

# PDF Generation Helper
def generate_pdf_report(incidents_list, total_ips):
    pdf = FPDF()
    pdf.add_page()
    
    # Title Header
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, "SOC Incident Triage & Forensic Report", ln=True, align="C")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Monitored IPs: {total_ips}", ln=True, align="C")
    pdf.ln(8)
    
    # Incident Entries
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, "Detected Security Incidents Summary", ln=True)
    pdf.ln(3)

    for idx, inc in enumerate(incidents_list, 1):
        pdf.set_font("Helvetica", "B", 10)
        # Color coding title line conceptually
        pdf.cell(0, 6, f"{idx}. [{inc['risk_level']}] {inc['incident_type']} - IP: {inc['source_ip']}", ln=True)
        
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(0, 5, f"Evidence: {inc['evidence']}")
        pdf.multi_cell(0, 5, f"Analyst Rationale: {inc['reason']}")
        pdf.ln(3)

    return bytes(pdf.output())

# Log Upload Section
with st.expander("📂 Click here to Upload Your Log Files", expanded=True):
    col_u1, col_u2 = st.columns(2)
    with col_u1:
        uploaded_linux = st.file_uploader("Upload Linux Log (.log, .txt)", type=["log", "txt"])
    with col_u2:
        uploaded_windows = st.file_uploader("Upload Windows Events (.json)", type=["json"])

all_events = []

if uploaded_linux is not None:
    linux_text = uploaded_linux.read().decode("utf-8")
    all_events.extend(parse_linux_content(linux_text))

if uploaded_windows is not None:
    windows_text = uploaded_windows.read().decode("utf-8")
    all_events.extend(parse_windows_content(windows_text))

# Built-in demo fallback
if not uploaded_linux and not uploaded_windows:
    st.info("💡 No files uploaded yet. Showing built-in demo sample data.")
    try:
        with open("linux_auth.log", "r") as f:
            all_events.extend(parse_linux_content(f.read()))
        with open("windows_events.json", "r") as f:
            all_events.extend(parse_windows_content(f.read()))
    except Exception:
        pass

incidents = analyze_events(all_events)

if incidents and all_events:
    total_ips_count = len(set(e["ip"] for e in all_events))
    
    # Top KPI Metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Monitored IPs", total_ips_count)
    col2.metric("Critical Alerts", sum(1 for i in incidents if i["risk_level"] == "CRITICAL"))
    col3.metric("High Alerts", sum(1 for i in incidents if i["risk_level"] == "HIGH"))
    col4.metric("Low / Benign", sum(1 for i in incidents if i["risk_level"] == "LOW"))

    st.markdown("---")

    # Interactive Search & Filters Section
    st.subheader("🎯 Threat Search & Telemetry Filters")
    f_col1, f_col2, f_col3, f_col4 = st.columns([1.5, 1, 1, 1])

    with f_col1:
        search_query = st.text_input("🔍 Search (IP, Username, or Keyword):", placeholder="e.g. 192.168, Eve, admin")
    with f_col2:
        risk_options = sorted(list(set(i["risk_level"] for i in incidents)))
        selected_risk = st.multiselect("Filter by Risk:", risk_options, default=risk_options)
    with f_col3:
        os_options = sorted(list(set(e["os_source"] for e in all_events)))
        selected_os = st.multiselect("Filter by OS:", os_options, default=os_options)
    with f_col4:
        event_options = sorted(list(set(e["event_type"] for e in all_events)))
        selected_events = st.multiselect("Filter Event Type:", event_options, default=event_options)

    # Filtered incidents
    filtered_incidents = [
        inc for inc in incidents
        if inc["risk_level"] in selected_risk and (
            not search_query or
            search_query.lower() in inc["source_ip"].lower() or
            search_query.lower() in inc["reason"].lower() or
            search_query.lower() in inc["evidence"].lower()
        )
    ]

    st.markdown("---")

    # Incidents Table Header & Export Buttons
    col_title, col_csv, col_pdf = st.columns([3, 1, 1])
    with col_title:
        st.subheader("🚨 Detected Incidents & Explainable Evidence")

    summary_data = [{
        "Source IP": inc["source_ip"],
        "Risk Level": inc["risk_level"],
        "Incident Type": inc["incident_type"],
        "Evidence": inc["evidence"],
        "Reason": inc["reason"]
    } for inc in filtered_incidents]
    
    incidents_df = pd.DataFrame(summary_data)

    if not incidents_df.empty:
        with col_csv:
            csv_data = incidents_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Export CSV",
                data=csv_data,
                file_name=f"incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )
        with col_pdf:
            pdf_bytes = generate_pdf_report(filtered_incidents, total_ips_count)
            st.download_button(
                label="📄 Export PDF",
                data=pdf_bytes,
                file_name=f"incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf",
                use_container_width=True
            )
        st.dataframe(incidents_df, use_container_width=True)
    else:
        st.warning("No incidents match your selected filters.")

    st.markdown("---")

    # Normalized Global Telemetry Explorer
    st.subheader("📋 Normalized Global Telemetry Explorer")
    events_df = pd.DataFrame(all_events)

    if not events_df.empty:
        filtered_df = events_df[
            (events_df["os_source"].isin(selected_os)) &
            (events_df["event_type"].isin(selected_events))
        ]

        if search_query:
            q = search_query.lower()
            filtered_df = filtered_df[
                filtered_df["ip"].astype(str).str.lower().str.contains(q) |
                filtered_df["user"].astype(str).str.lower().str.contains(q) |
                filtered_df["details"].astype(str).str.lower().str.contains(q)
            ]

        display_cols = ["timestamp", "os_source", "category", "event_type", "user", "ip", "details"]
        available_cols = [c for c in display_cols if c in filtered_df.columns]
        st.dataframe(filtered_df[available_cols], use_container_width=True)

    st.markdown("---")

    # Forensic Timeline Investigation
    st.subheader("🔍 Forensic Timeline Investigation")
    available_ips = sorted(list(set(inc["source_ip"] for inc in filtered_incidents))) if filtered_incidents else sorted(list(set(inc["source_ip"] for inc in incidents)))
    
    if available_ips:
        selected_ip = st.selectbox("Select IP to Investigate:", available_ips)
        target_incident = next((i for i in incidents if i["source_ip"] == selected_ip), None)

        if target_incident:
            st.write(f"**Threat Assessment:** `{target_incident['risk_level']}` | **Incident:** `{target_incident['incident_type']}`")
            st.info(f"**Analyst Rationale:** {target_incident['reason']}")

            timeline_df = pd.DataFrame(target_incident["timeline"])
            t_cols = [c for c in ["timestamp", "os_source", "event_type", "user", "details"] if c in timeline_df.columns]
            st.dataframe(timeline_df[t_cols], use_container_width=True)
else:
    st.warning("No events found in the uploaded file(s).")