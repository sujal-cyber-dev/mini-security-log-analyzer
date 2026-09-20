<div align="center">

# 🛡️ Mini SIEM & Security Log Analyzer
**Architect & Primary Maintainer:** [Sujal](https://github.com/sujal-cyher-dev)  
*Enterprise-grade Telemetry Pipeline | Ingestion Engine | SOC Threat Analytics*

[![License: Proprietary/Academic](https://img.shields.io/badge/License-Attribution%20Required-blue.svg)](LICENSE)
[![Security Architecture](https://img.shields.io/badge/Architecture-Splunk%20%2F%20Wazuh%20Model-orange.svg)](#)
[![Identity Verified](https://img.shields.io/badge/Author-Sujal-success.svg)](#)

> **Notice on Academic Integrity:** This codebase embodies original engineering work. Forking for review is permitted, but claiming or submitting this system as uncredited individual work violates academic integrity norms.
</div>

---
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