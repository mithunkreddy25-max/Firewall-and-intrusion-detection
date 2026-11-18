# Campus Secure: Next-Gen Network Security & SOC Monitoring Platform
*Firewall and Intrusion Detection System Deployment for a College Network*

## Overview
**Campus Secure** is a professional, feature-rich **Security Operations Center (SOC) monitoring and defense simulation platform** for college campus networks. It provides a real-time cybersecurity dashboard, interactive Vis.js network topology with connection animations, configurable priority-based firewall rules, multi-vector intrusion detection (IDS) with automated severity scoring (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), live security telemetry charts, audit logs with CSV export, and an executive briefing generator.

| Zone | Subnet CIDR | Role & Trust Profile |
|------|-------------|----------------------|
| **Student Lab** | `10.10.10.0/24` | General student computing; restricted from internal server segments |
| **Faculty** | `10.10.20.0/24` | Academic and faculty workstations; regulated administrative reach |
| **Administration** | `10.10.30.0/24` | High-value segment housing student records, databases & finance |
| **Public Web Server / DMZ** | `10.10.40.0/24` | Demilitarized zone exposing public HTTP/HTTPS web services |

The backend is built with **Python Flask** and **SQLite**, with all telemetry and statistics computed directly from persisted events. The frontend utilizes **Inter**, **JetBrains Mono**, **Chart.js**, and **vis-network**.

> **Important:** This is a **software simulation platform** designed for educational, demonstration, and security operations training. No actual kernel network packets are filtered.

---

## Key Features

### 1. Professional Security Dashboard (`/dashboard`)
* **Cybersecurity SOC Dark Theme:** Designed with a high-contrast dark palette, glowing threat beacons, and glassmorphic card surfaces.
* **Live Telemetry Metric Cards:** Total Inspected Packets, Allowed Packets (% ratio), Blocked Packets (% ratio), and IDS Threat Alerts.
* **Threat Posture Indicator:** Dynamic beacon reflecting campus risk level (`NORMAL`, `ELEVATED`, `HIGH`, `CRITICAL`) based on live incident severity.
* **Auto-Simulate Live Stream:** Toggle switch that streams periodic safe and suspicious campus traffic in real time.
* **Interactive Chart.js Visualizations:**
  * **Traffic Volume Over Time:** Line chart of allowed vs. blocked packet flows.
  * **Attack Vector Distribution:** Doughnut chart categorizing detected threat signatures.

### 2. Advanced Network Topology
* **Interactive Vis.js Canvas:** Visualizes Student Lab, Faculty, Administration, DMZ, and the central Campus Firewall & IDS Core.
* **Animated Connections:** Links pulse in green (allowed), crimson (blocked), or amber (threat alert) as traffic flows.
* **Subnet & Legend Display:** Color-coded zones with CIDR addresses and trunk bandwidth specifications.

### 3. Configurable Firewall Policy Engine (`/rules`)
* **Priority-Based Rule Evaluation:** Sequential evaluation where lowest priority number takes precedence (e.g., Rule #10 before Rule #100).
* **Flexible Matching:** Source, Destination, Port lists (`80,443`), ranges (`8000-8080`), or wildcard `*`.
* **Human-Readable Decision Reasons:** Every allow or block decision records the exact rule matched (e.g. `Rule #20: Allow Public DMZ Web Services` or `Default Fallback Policy (DENY)`).
* **Full Rule Management:** Enable/disable rules with live toggle switches, add custom rules, delete rules, or reset to recommended defaults.

### 4. Advanced Intrusion Detection System (IDS)
* **Port Scanning Detection:** Multi-port sweep recognition targeting perimeter or internal hosts (`HIGH` severity).
* **Repeated Login / Brute-Force Detection:**
  * SSH (port 22) brute force (`HIGH` severity).
  * Remote Desktop RDP (port 3389) brute force (`HIGH` severity).
  * Web authentication brute force on DMZ (port 80/443) (`MEDIUM` severity).
  * Database authentication brute force on Administration (port 1433/3306) (`CRITICAL` severity).
* **Unauthorized Access Detection:**
  * DMZ Inbound Lateral Movement (`CRITICAL` severity).
  * Student Lab direct breach attempt on Administration (`CRITICAL` severity).
  * Web application exploit on allowed port (`HIGH` severity).
* **Unusual Traffic Frequency:** Detects high-rate packet bursts and potential DoS flood anomalies.
* **Suspicious Port Probing:** Flags prohibited protocol probes (SMB 445, MS-RPC 135, NetBIOS 139, Telnet 23).
* **Automated Severity Scoring:** Assigns `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `SAFE`.

### 5. Security Analytics (`/analytics`)
* Incident severity distribution bar charts.
* Attack vector classification breakdown.
* Top 5 most active traffic source subnets.
* Top 5 most targeted destination subnets.

### 6. Security Event Management
* **Real-Time Live Search:** Instant keyword filtering across source, destination, port, decision, and alert names.
* **Multi-Criteria Dropdown Filters:** Filter by Severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `SAFE`) and Decision (`ALLOWED`, `BLOCKED`).
* **Security Event Dossier Modal:** Click any event row to inspect full telemetry, matched rule, severity, and SOC Analyst remediation advice.
* **CSV Export:** Download full audit log via `/api/export_csv`.

### 7. Executive Reporting & System Controls
* **Executive Security Briefing (`/report`):** Formal report with executive summary, posture score, incident distribution, and priority recommendations. Print or export to PDF via `Ctrl+P`.
* **System Settings (`/settings`):** Adjust IDS sensitivity mode (Standard, Strict, Aggressive), default fallback action, and detection thresholds.
* **Administrator Authentication (`/login` / `/logout`):** Session-based login (Default credentials: `admin` / `admin123`).

---

## Repository Layout
```
College_Network_Security/
├─ app.py                      # Flask backend, rule engine, IDS, APIs, session auth
├─ requirements.txt            # Python dependencies (Flask, Flask-Cors)
├─ database.db                 # SQLite DB (events, firewall_rules, system_settings)
├─ test_security.py            # Automated test suite (9 unit & integration tests)
├─ templates/
│   ├─ dashboard.html          # Main SOC operations dashboard
│   ├─ simulation.html         # Interactive packet injector & presets
│   ├─ analytics.html          # Deep security analytics & charts
│   ├─ rules.html              # Firewall rules policy manager
│   ├─ settings.html           # Platform & detection engine settings
│   ├─ report.html             # Printable executive security brief
│   └─ login.html              # Administrator authentication
├─ static/
│   ├─ css/
│   │   └─ style.css           # Modern cybersecurity dark theme
│   └─ js/
│       ├─ dashboard.js        # Live telemetry, Chart.js, Vis.js, event modal
│       └─ simulation.js       # Simulation form & scenario handler
└─ README.md                   # Platform documentation
```

---

## Setup & Running

1. **Activate Virtual Environment:**
   ```powershell
   .\venv\Scripts\Activate.ps1
   ```

2. **Run Automated Test Suite:**
   ```powershell
   python test_security.py
   ```
   *(All 9 tests pass with 100% verification)*

3. **Start the Platform:**
   ```powershell
   python app.py
   ```
   The platform will bind to `http://127.0.0.1:5000`.

4. **Access the SOC Interface:**
   * Dashboard: `http://127.0.0.1:5000/dashboard`
   * Traffic Simulator: `http://127.0.0.1:5000/simulation`
   * Security Analytics: `http://127.0.0.1:5000/analytics`
   * Firewall Rules: `http://127.0.0.1:5000/rules`
   * Executive Report: `http://127.0.0.1:5000/report`
   * Settings: `http://127.0.0.1:5000/settings`
   * Admin Login: `http://127.0.0.1:5000/login` *(admin / admin123)*

---

## Sample Test Scenarios
| # | Source | Destination | Port | Protocol | Expected Decision | IDS Alert | Severity |
|---|--------|-------------|------|----------|-------------------|-----------|----------|
| 1 | Student Lab | Student Lab | 22 | TCP | **ALLOWED** | – | `SAFE` |
| 2 | Faculty | Public Web Server / DMZ | 80 | TCP | **ALLOWED** | – | `SAFE` |
| 3 | Student Lab | Faculty | 22 | TCP | **BLOCKED** | – | `LOW` |
| 4 | Student Lab → Faculty (3x) | 22 | TCP | **BLOCKED** | **Repeated SSH Scan Detected** | `HIGH` |
| 5 | Any → Any (5 ports) | * | TCP | **BLOCKED** | **Suspicious Port Scan Detected** | `HIGH` |
| 6 | Student Lab | Administration | 1433 | TCP | **BLOCKED** | **Restricted Admin Zone Access** | `CRITICAL` |
| 7 | Public DMZ | Faculty | 22 | TCP | **BLOCKED** | **DMZ Lateral Movement** | `CRITICAL` |
