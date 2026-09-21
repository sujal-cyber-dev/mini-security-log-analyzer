# app.py
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
from fpdf import FPDF
from datetime import datetime
from analyzer import parse_linux_content, parse_windows_content, analyze_events
from stream_collector import follow_file

st.set_page_config(page_title="Security Log Analyzer & SIEM", layout="wide")

st.title("🛡️ Mini SIEM - Security Log Analyzer")
st.markdown("Automated ingestion, telemetry normalization, explainable threat detection, visual analytics, and incident response.")

# Helper: Free Public IP Intelligence & Geo-Lookup (Cached to optimize speed)
@st.cache_data(ttl=3600)
def lookup_ip_intelligence(ip):
    # Simulated Global Threat Nodes for Private/Demo IPs to show realistic SOC telemetry
    demo_geo_map = {
        "192.168.1.105": {"country": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6173, "isp": "Rostelecom PJSC", "org": "Mirai Botnet Ingress"},
        "172.16.0.40": {"country": "China", "city": "Shanghai", "lat": 31.2304, "lon": 121.4737, "isp": "China Telecom", "org": "APT-41 C2 Node"},
        "10.0.0.15": {"country": "United States", "city": "Ashburn", "lat": 39.0438, "lon": -77.4874, "isp": "Amazon AWS Cloud", "org": "Credential Stuffer"},
        "172.16.0.29": {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "isp": "DigitalOcean LLC", "org": "Tor Exit Gateway"}
    }
    
    if ip in demo_geo_map:
        data = demo_geo_map[ip]
        return {
            "status": "Public",
            "country": data["country"],
            "city": data["city"],
            "lat": data["lat"],
            "lon": data["lon"],
            "isp": data["isp"],
            "org": data["org"],
            "reputation": "External Ingress (Threat Flagged)"
        }

    if ip.startswith(("10.", "192.168.", "172.16.", "127.", "Localhost", "Unknown")):
        return {
            "status": "Private/Local",
            "country": "Internal Network",
            "city": "Private Subnet",
            "lat": 20.2961,
            "lon": 85.8245,
            "isp": "Local Subnet / Router",
            "org": "Internal Infrastructure",
            "reputation": "Internal Asset (Low Risk)"
        }
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp,org,as,query", timeout=3).json()
        if res.get("status") == "success":
            return {
                "status": "Public",
                "country": res.get("country", "Unknown"),
                "city": res.get("city", "Unknown"),
                "lat": res.get("lat", 0.0),
                "lon": res.get("lon", 0.0),
                "isp": res.get("isp", "Unknown ISP"),
                "org": res.get("org", "Unknown Org"),
                "reputation": "External Ingress (Flagged for Threat Correlation)"
            }
    except Exception:
        pass
    return {
        "status": "Unknown",
        "country": "Unknown",
        "city": "Unknown",
        "lat": 0.0,
        "lon": 0.0,
        "isp": "Unknown ISP",
        "org": "Unknown Organization",
        "reputation": "Unverified"
    }
# Universal Safe PDF Generation Helper (Compatible with both fpdf & fpdf2)
def generate_pdf_report(incidents_list, total_ips):
    pdf = FPDF(orientation='P', unit='mm', format='A4')
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(190, 10, "SOC Incident Triage & Forensic Report", ln=1, align="C")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(190, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Monitored IPs: {total_ips}", ln=1, align="C")
    pdf.ln(6)
    
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(190, 8, "Detected Security Incidents Summary", ln=1)
    pdf.ln(2)

    for idx, inc in enumerate(incidents_list, 1):
        risk = str(inc.get('risk_level', 'LOW')).encode('latin-1', 'replace').decode('latin-1')
        itype = str(inc.get('incident_type', '')).encode('latin-1', 'replace').decode('latin-1')
        ip = str(inc.get('source_ip', '')).encode('latin-1', 'replace').decode('latin-1')
        evidence = str(inc.get('evidence', '')).encode('latin-1', 'replace').decode('latin-1')
        reason = str(inc.get('reason', '')).encode('latin-1', 'replace').decode('latin-1')

        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(190, 6, f"{idx}. [{risk}] {itype} - Source: {ip}", ln=1)
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(190, 5, f"Evidence: {evidence}")
        pdf.multi_cell(190, 5, f"Analyst Rationale: {reason}")
        pdf.ln(3)

    return bytes(pdf.output())

# --- Real-Time Streaming Toggle ---
st.sidebar.markdown("### ⚙️ Mode Settings")
stream_mode = st.sidebar.radio("Log Source Mode:", ["Batch File Upload", "🔴 Live Telemetry Stream"])

if stream_mode == "🔴 Live Telemetry Stream":
    st.info("🟢 Real-Time Collector is actively listening for live telemetry in 'live_stream.log'...")
    live_placeholder = st.empty()

    if "live_events" not in st.session_state:
        st.session_state.live_events = []

    live_file_path = "live_stream.log"

    for new_line in follow_file(live_file_path):
        parsed = parse_linux_content(new_line)
        if parsed:
            st.session_state.live_events.extend(parsed)
            st.session_state.live_events = st.session_state.live_events[-150:]

        live_incidents = analyze_events(st.session_state.live_events)

        with live_placeholder.container():
            col1, col2 = st.columns(2)
            col1.metric("Live Telemetry Count", len(st.session_state.live_events))
            col2.metric("Detected Critical Incidents", len(live_incidents))

            st.subheader("🚨 Live Ingested Incidents")
            if live_incidents:
                st.dataframe(live_incidents, use_container_width=True)
            else:
                st.write("Waiting for incoming attack traffic...")

    st.stop()

# Ingestion Upload Area
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
    
    # 1. Top KPI Metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Monitored IPs", total_ips_count)
    col2.metric("Critical Alerts", sum(1 for i in incidents if i["risk_level"] == "CRITICAL"))
    col3.metric("High Alerts", sum(1 for i in incidents if i["risk_level"] == "HIGH"))
    col4.metric("Low / Benign", sum(1 for i in incidents if i["risk_level"] == "LOW"))

    st.markdown("---")

    # 2. Interactive Search & Filters
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

    # Filtered dataset
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

    # 3. Visual Attack Analytics (Charts & Geospatial Map)
    st.subheader("📊 SOC Threat Analytics & Ingress Map")
    c1, c2 = st.columns(2)

    with c1:
        risk_counts = pd.Series([i["risk_level"] for i in filtered_incidents]).value_counts().reset_index()
        risk_counts.columns = ["Risk Level", "Count"]
        color_map = {"CRITICAL": "#ff4b4b", "HIGH": "#ffa500", "MEDIUM": "#ffe600", "LOW": "#2ecc71"}
        fig_donut = px.pie(risk_counts, names="Risk Level", values="Count", hole=0.5,
                           title="Alert Distribution by Severity",
                           color="Risk Level", color_discrete_map=color_map)
        st.plotly_chart(fig_donut, use_container_width=True)

    with c2:
        all_users = [e["user"] for e in all_events if e.get("user") and e["user"] not in ["Unknown", "SYSTEM", "System"]]
        if all_users:
            user_counts = pd.Series(all_users).value_counts().head(5).reset_index()
            user_counts.columns = ["Target Account", "Attempt Count"]
            fig_bar = px.bar(user_counts, x="Target Account", y="Attempt Count", 
                             title="Top Targeted Accounts", text_auto=True,
                             color_discrete_sequence=["#1f77b4"])
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("No target accounts found for chart.")

    # GeoIP Threat Map
    # 3D Geospatial Threat Intelligence (Deep Space Globe)
    map_points = []
    for inc in filtered_incidents:
        geo = lookup_ip_intelligence(inc["source_ip"])
        if geo["lat"] != 0.0 and geo["lon"] != 0.0:
            map_points.append({
                "lat": geo["lat"],
                "lon": geo["lon"],
                "IP": inc["source_ip"],
                "Country": geo["country"],
                "City": geo["city"],
                "Threat": inc.get("incident_type", "Suspicious Activity"),
                "Risk": inc.get("risk_level", "LOW")
            })

    if map_points:
        st.markdown("---")
        st.subheader("🌍 3D Geospatial Threat Ingress (Deep Space Intelligence)")
        geo_df = pd.DataFrame(map_points)

        col_tbl, col_globe = st.columns([1.1, 1.9])

        with col_tbl:
            st.markdown("##### 🎯 Target Ingress Vectors")
            # Attacker options for auto-focus selection
            attacker_options = [
                f"{row['IP']} | {row['City']}, {row['Country']}" 
                for _, row in geo_df.iterrows()
            ]
            selected_option = st.selectbox("Select Attacker to Lock Coordinates:", attacker_options)
            
            selected_idx = attacker_options.index(selected_option)
            target = geo_df.iloc[selected_idx]
            
            target_lat = target["lat"]
            target_lon = target["lon"]

            # Live intelligence lookup for ISP & Datacenter details
            target_intel = lookup_ip_intelligence(target['IP'])

            st.info(f"""
            🎯 **Locked Target:** `{target['IP']}`
            
            📍 **Incident Origin:** {target['City']}, {target['Country']}
            🏢 **ISP Organization:** `{target_intel.get('org', target_intel.get('isp', 'Unknown ISP'))}`
            🛰️ **ISP Gateway / Routing POP:** {target_intel.get('city', 'Unknown')}, {target_intel.get('country', 'Unknown')}
            🌐 **ISP Gateway Coordinates:** `{target_lat}°, {target_lon}°`
            
            🚨 **Threat Signature:** `{target['Threat']}` (`{target['Risk']}`)
            """)

            # Quick overview table
            st.dataframe(geo_df[["IP", "Country", "Risk"]], height=180, use_container_width=True)

       with col_globe:
            fig_globe = go.Figure()

            # 1. Base Ingress Threat Vectors (Glowing Red Nodes)
            fig_globe.add_trace(go.Scattergeo(
                lat=geo_df["lat"],
                lon=geo_df["lon"],
                mode="markers+text",
                text=geo_df["IP"],
                textposition="top center",
                textfont=dict(color="#00FFA3", size=10, family="Courier New"),
                marker=dict(
                    size=10,
                    color="#FF3344",
                    symbol="circle",
                    opacity=0.9,
                    line=dict(width=1.5, color="#FFAA00")
                ),
                name="Threat Vectors"
            ))

            # 2. Outer Atmospheric Radar Pulse (Visual Orbit Depth)
            fig_globe.add_trace(go.Scattergeo(
                lat=[target_lat],
                lon=[target_lon],
                mode="markers",
                marker=dict(
                    size=28,
                    color="rgba(255, 51, 68, 0.2)",
                    symbol="circle",
                    line=dict(width=2, color="#00FFA3")
                ),
                name="Radar Wave"
            ))

            # 3. Precision Target Locked Reticle (Center Core)
            fig_globe.add_trace(go.Scattergeo(
                lat=[target_lat],
                lon=[target_lon],
                mode="markers",
                marker=dict(
                    size=14,
                    color="#FFCC00",
                    symbol="circle",
                    line=dict(width=2, color="#FFFFFF")
                ),
                name="Active Lock"
            ))

            # 4. Cinematic Space & Earth Shading
            fig_globe.update_geos(
                projection_type="orthographic",
                projection_rotation=dict(lon=target_lon, lat=target_lat, roll=0),
                showocean=True,
                oceancolor="#020813",          # Ultra-deep midnight abyss ocean
                showland=True,
                landcolor="#12251d",           # Tactical night satellite land tone
                showlakes=True,
                lakecolor="#020813",
                showrivers=True,
                rivercolor="#07182e",
                showcountries=True,
                countrycolor="#1e4d38",        # Subtle boundary grid
                countrywidth=0.8,
                coastlinecolor="#00FFA3",      # Atmospheric neon horizon edge
                coastlinewidth=1.2,
                bgcolor="#000000"              # Deep space black
            )

            fig_globe.update_layout(
                height=520,
                paper_bgcolor="#000000",
                plot_bgcolor="#000000",
                margin={"r": 0, "t": 0, "l": 0, "b": 0},
                showlegend=False
            )

            st.plotly_chart(fig_globe, use_container_width=True)

    st.markdown("---")

    # 4. Detected Incidents & Export
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

    # 5. Normalized Global Telemetry Explorer
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

    # 6. Forensic Investigation & Automated SOC Remediation Playbook
    st.subheader("🔍 Forensic Timeline Investigation & SOC Remediation")
    available_ips = sorted(list(set(inc["source_ip"] for inc in filtered_incidents))) if filtered_incidents else sorted(list(set(inc["source_ip"] for inc in incidents)))
    
    if available_ips:
        selected_ip = st.selectbox("Select IP to Investigate:", available_ips)
        target_incident = next((i for i in incidents if i["source_ip"] == selected_ip), None)

        if target_incident:
            intel = lookup_ip_intelligence(selected_ip)
            st.markdown(f"**Threat Assessment:** `{target_incident['risk_level']}` | **Incident:** `{target_incident['incident_type']}` | **Origin:** `{intel['city']}, {intel['country']}`")
            st.info(f"**Analyst Rationale:** {target_incident['reason']}")

            with st.expander("🛠️ Automated SOC Remediation Playbook (Actionable Response)", expanded=True):
                st.write("Execute these recommended countermeasures on affected perimeter systems:")
                block_linux = f"sudo iptables -A INPUT -s {selected_ip} -j DROP"
                block_win = f'New-NetFirewallRule -DisplayName "Block {selected_ip}" -Direction Inbound -RemoteAddress {selected_ip} -Action Block'
                
                col_pb1, col_pb2 = st.columns(2)
                with col_pb1:
                    st.code(block_linux, language="bash")
                    st.caption("Linux Iptables Block Rule")
                with col_pb2:
                    st.code(block_win, language="powershell")
                    st.caption("Windows Firewall Block Rule")

            timeline_df = pd.DataFrame(target_incident["timeline"])
            t_cols = [c for c in ["timestamp", "os_source", "event_type", "user", "details"] if c in timeline_df.columns]
            st.dataframe(timeline_df[t_cols], use_container_width=True)
else:
    st.warning("No events found in the uploaded file(s).")