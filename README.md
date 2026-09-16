# 🛡️ Cross-Platform Security Log Analyzer & Incident Investigator

A lightweight, explainable SIEM-like log analysis tool designed to ingest, normalize, and detect suspicious authentication activity across both **Linux** (`auth.log`) and **Windows** (Security Event IDs 4624/4625) telemetry.

## 🚀 Features
- **Heterogeneous Log Ingestion:** Parses raw Linux syslog and Windows JSON event exports into a unified JSON data schema.
- **Correlation & Attack Detection:** Identifies brute-force patterns and flags critical compromise events (repeated failures followed by successful authentication).
- **Explainable Threat Alerts:** Instead of simple flags, each alert provides human-readable context, risk scoring (Low/Medium/Critical), and direct forensic evidence.
- **Forensic Triage Dashboard:** Built with Streamlit to enable incident responders to filter by IP and inspect chronological attack timelines.

## 🛠️ Tech Stack
- **Language:** Python 3
- **Frontend / Dashboard:** Streamlit
- **Data Processing:** Pandas, Regex, JSON

## 📦 Installation & Setup

1. Clone this repository:
   ```bash
   git clone [https://github.com/](https://github.com/)<your-username>/mini-security-log-analyzer.git
   cd mini-security-log-analyzer