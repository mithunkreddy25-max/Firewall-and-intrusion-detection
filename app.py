import io
import csv
import json
import random
import sqlite3
from collections import defaultdict, deque
from datetime import datetime, timezone

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    Response,
    flash
)

app = Flask(__name__)
app.secret_key = "campus-network-security-soc-secret-key-2026"

DB_PATH = "database.db"

# College network zones
ZONES = {
    "Student Lab": "10.10.10.0/24",
    "Faculty": "10.10.20.0/24",
    "Administration": "10.10.30.0/24",
    "Public Web Server / DMZ": "10.10.40.0/24"
}

# IDS in-memory state tracking
ssh_attempts = defaultdict(int)
port_scans = defaultdict(set)
rdp_attempts = defaultdict(int)
login_attempts = defaultdict(int)
zone_request_times = defaultdict(lambda: deque(maxlen=40))

# Default standard recommended firewall rules
DEFAULT_RULES = [
    (10, "Allow Intra-Zone Trust", "SAME_ZONE", "SAME_ZONE", "*", "ANY", "allow", 1, "Permit trusted local communication within the same subnet"),
    (20, "Allow Public DMZ Web Services", "ANY", "Public Web Server / DMZ", "80,443", "TCP", "allow", 1, "Allow all campus zones access to public HTTP/HTTPS web services"),
    (30, "Allow Faculty DMZ Management (Optional)", "Faculty", "Public Web Server / DMZ", "22,8080", "TCP", "allow", 0, "Optional administrative rule: allow Faculty remote access to DMZ (disabled by default)"),
    (40, "Block Student Lab to Admin Database", "Student Lab", "Administration", "1433,3306,5432,445", "ANY", "deny", 1, "Strictly block Student Lab access to sensitive administration databases and SMB shares"),
    (50, "Block DMZ Inbound Lateral Movement", "Public Web Server / DMZ", "ANY", "*", "ANY", "deny", 1, "Prevent compromised DMZ systems from initiating inbound lateral connections to college LAN"),
    (100, "Default Inter-Zone Deny", "ANY", "ANY", "*", "ANY", "deny", 1, "Zero Trust baseline: block all unauthorized inter-zone network traffic")
]

# ---------------- DATABASE ----------------

def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()

    # 1. Events Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source TEXT,
            destination TEXT,
            port INTEGER,
            protocol TEXT,
            decision TEXT,
            alerts TEXT,
            decision_reason TEXT DEFAULT 'Firewall Policy Evaluation',
            severity TEXT DEFAULT 'LOW'
        )
    """)

    # Migration check for existing installations
    cur.execute("PRAGMA table_info(events)")
    cols = [r[1] for r in cur.fetchall()]
    if "decision_reason" not in cols:
        cur.execute("ALTER TABLE events ADD COLUMN decision_reason TEXT DEFAULT 'Firewall Policy Evaluation'")
    if "severity" not in cols:
        cur.execute("ALTER TABLE events ADD COLUMN severity TEXT DEFAULT 'LOW'")

    # 2. Firewall Rules Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS firewall_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            priority INTEGER NOT NULL,
            name TEXT NOT NULL,
            source TEXT NOT NULL,
            destination TEXT NOT NULL,
            port TEXT NOT NULL,
            protocol TEXT NOT NULL,
            action TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            description TEXT
        )
    """)

    cur.execute("SELECT COUNT(*) FROM firewall_rules")
    if cur.fetchone()[0] == 0:
        seed_default_rules(conn)

    # 3. System Settings Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)

    default_settings = {
        "ids_sensitivity": "standard",
        "default_firewall_action": "deny",
        "ssh_threshold": "3",
        "port_scan_threshold": "5",
        "rate_limit_threshold": "8",
        "continuous_simulation": "off"
    }
    for k, v in default_settings.items():
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES (?, ?)", (k, v))

    conn.commit()
    conn.close()


def seed_default_rules(conn):
    conn.executemany("""
        INSERT INTO firewall_rules (priority, name, source, destination, port, protocol, action, enabled, description)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, DEFAULT_RULES)


def get_setting(key, default=None):
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        cur = conn.cursor()
        cur.execute("SELECT value FROM system_settings WHERE key = ?", (key,))
        row = cur.fetchone()
        conn.close()
        return row[0] if row else default
    except Exception:
        return default


def set_setting(key, value):
    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)", (key, str(value)))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def assign_severity(alerts, decision):
    """Assigns LOW, MEDIUM, HIGH, or CRITICAL severity to the event."""
    if not alerts:
        if str(decision).lower() in ("deny", "blocked"):
            return "LOW"
        return "SAFE"

    crit_keywords = ["DMZ to Internal", "Restricted Administration Zone", "Database Brute Force", "Lateral Movement"]
    high_keywords = ["Port Scan", "SSH Scan", "RDP Brute Force", "Web Application Exploit", "Traffic Frequency", "High-Rate Burst"]
    med_keywords = ["HTTP/HTTPS Brute Force", "Suspicious Port Activity", "Prohibited Protocol", "Repeated Login", "Cross-Zone"]

    for a in alerts:
        if any(k in a for k in crit_keywords):
            return "CRITICAL"
    for a in alerts:
        if any(k in a for k in high_keywords):
            return "HIGH"
    for a in alerts:
        if any(k in a for k in med_keywords):
            return "MEDIUM"

    return "LOW"


def log_event(src, dst, port, protocol, decision, alerts, reason=None, severity=None):
    if reason is None:
        reason = "Firewall Policy Evaluation"
    if severity is None:
        severity = assign_severity(alerts, decision)

    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("""
        INSERT INTO events
        (timestamp, source, destination, port, protocol, decision, alerts, decision_reason, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now(timezone.utc).isoformat(),
        src, dst, port, protocol, decision,
        json.dumps(alerts),
        reason,
        severity
    ))
    conn.commit()
    conn.close()


# ---------------- FIREWALL RULE ENGINE ----------------

def firewall_decision_detailed(src, dst, port, protocol):
    """
    Evaluates packet against configurable rules in firewall_rules table in priority order.
    Returns (action, reason).
    """
    if src not in ZONES or dst not in ZONES:
        return "deny", "Invalid network zone"

    try:
        port = int(port)
    except (ValueError, TypeError):
        return "deny", "Invalid port number"

    if not 1 <= port <= 65535:
        return "deny", "Port out of valid range (1-65535)"

    protocol = str(protocol).lower()
    if protocol not in ("tcp", "udp"):
        return "deny", "Unsupported protocol (TCP/UDP only)"

    try:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        cur = conn.cursor()
        cur.execute("""
            SELECT priority, name, source, destination, port, protocol, action
            FROM firewall_rules
            WHERE enabled = 1
            ORDER BY priority ASC
        """)
        rules = cur.fetchall()

        cur.execute("SELECT value FROM system_settings WHERE key = 'default_firewall_action'")
        row = cur.fetchone()
        default_action = row[0] if row else "deny"
        conn.close()
    except Exception:
        rules = []
        default_action = "deny"

    # Evaluate rules by priority
    for r_prio, r_name, r_src, r_dst, r_port, r_proto, r_act in rules:
        if r_src == "SAME_ZONE" and r_dst == "SAME_ZONE":
            if src == dst:
                return r_act.lower(), f"Rule #{r_prio}: {r_name}"
            continue

        src_match = (r_src == "*" or r_src.upper() == "ANY" or r_src == src)
        dst_match = (r_dst == "*" or r_dst.upper() == "ANY" or r_dst == dst)
        if not (src_match and dst_match):
            continue

        proto_match = (r_proto == "*" or r_proto.upper() == "ANY" or r_proto.lower() == protocol)
        if not proto_match:
            continue

        port_match = False
        if r_port == "*" or r_port.upper() == "ANY":
            port_match = True
        else:
            ports = [p.strip() for p in str(r_port).split(",") if p.strip()]
            for p_str in ports:
                if "-" in p_str:
                    try:
                        p_min, p_max = map(int, p_str.split("-"))
                        if p_min <= port <= p_max:
                            port_match = True
                            break
                    except ValueError:
                        pass
                else:
                    try:
                        if int(p_str) == port:
                            port_match = True
                            break
                    except ValueError:
                        pass

        if port_match:
            return r_act.lower(), f"Rule #{r_prio}: {r_name}"

    # Fallback policy
    fallback = default_action.lower()
    return fallback, f"Default Fallback Policy ({fallback.upper()})"


def firewall_decision(src, dst, port, protocol):
    """Preserves original signature returning action string 'allow' or 'deny'."""
    action, _ = firewall_decision_detailed(src, dst, port, protocol)
    return action


# ---------------- INTRUSION DETECTION SYSTEM ----------------

def ids_check(src, dst, port, protocol, attack_type=None):
    """
    Simulated Intrusion Detection Engine.
    Detects port scans, brute force, unauthorized zone crossing, rate anomalies, and suspicious port probing.
    """
    alerts = []
    protocol = str(protocol).lower()
    try:
        port = int(port)
    except (ValueError, TypeError):
        return alerts

    key = (src, dst)
    now_ts = datetime.now(timezone.utc).timestamp()

    # Track traffic frequency per source
    times = zone_request_times[src]
    times.append(now_ts)
    rate_threshold = int(get_setting("rate_limit_threshold", 8))
    if attack_type in ("traffic_frequency", "dos_burst") or (len(times) >= 25 and (times[-1] - times[0]) < 1.0):
        alerts.append("Unusual Traffic Frequency: High-Rate Burst / Flooding Anomaly")
        times.clear()

    # 1. Repeated SSH connection attempts
    if protocol == "tcp" and port == 22:
        ssh_attempts[key] += 1
        ssh_thresh = int(get_setting("ssh_threshold", 3))
        if ssh_attempts[key] >= ssh_thresh:
            alerts.append("Repeated SSH Scan Detected")
            ssh_attempts[key] = 0

    # 2. Port scanning detection
    if protocol == "tcp":
        port_scans[key].add(port)
        ps_thresh = int(get_setting("port_scan_threshold", 5))
        if len(port_scans[key]) >= ps_thresh or attack_type == "port_scan":
            alerts.append("Suspicious Port Scan Detected")
            port_scans[key].clear()

    # 3. Repeated login / brute force attempts
    if attack_type == "web_login_brute_force" or (port in (80, 443) and attack_type == "repeated_login"):
        alerts.append("Repeated Login Attempts Detected (HTTP/HTTPS Brute Force)")
    elif attack_type == "rdp_brute_force" or (protocol == "tcp" and port == 3389):
        if attack_type == "rdp_brute_force":
            alerts.append("Repeated Login Attempts Detected (RDP Brute Force)")
        else:
            rdp_attempts[key] += 1
            if rdp_attempts[key] >= 3:
                alerts.append("Repeated Login Attempts Detected (RDP Brute Force)")
                rdp_attempts[key] = 0
    elif attack_type == "db_brute_force" or (port in (1433, 3306, 5432) and attack_type == "repeated_login"):
        alerts.append("Repeated Login Attempts Detected (Database Brute Force)")
    elif attack_type == "repeated_login":
        alerts.append("Repeated Login Attempts Detected")

    # 4. Unauthorized zone crossings
    if src == "Public Web Server / DMZ" and dst != "Public Web Server / DMZ":
        alerts.append("Unauthorized Access Attempt: DMZ to Internal Network (Lateral Movement)")

    if src == "Student Lab" and dst == "Administration":
        alerts.append("Unauthorized Access Attempt: Restricted Administration Zone Access")

    if attack_type == "web_exploit":
        alerts.append("Unauthorized Access Attempt: Web Application Exploit Detected")
    elif attack_type == "unauthorized_access" and not any("Unauthorized Access" in a for a in alerts):
        alerts.append(f"Unauthorized Access Attempt: Prohibited Cross-Zone Access ({src} -> {dst})")

    # 5. Suspicious / dangerous port activity across inter-zone boundaries
    if src != dst and port in (445, 135, 139, 23, 69):
        port_names = {445: "SMB (Port 445)", 135: "MS-RPC (Port 135)", 139: "NetBIOS (Port 139)", 23: "Telnet (Port 23)", 69: "TFTP (Port 69)"}
        p_label = port_names.get(port, f"Port {port}")
        alerts.append(f"Suspicious Port Activity: Prohibited Service Probe ({p_label})")

    # Deduplicate while preserving order
    seen = set()
    unique_alerts = []
    for a in alerts:
        if a not in seen:
            seen.add(a)
            unique_alerts.append(a)

    return unique_alerts


# ---------------- TRAFFIC PATTERN GENERATORS ----------------

def generate_suspicious_traffic():
    """
    Generates random suspicious traffic patterns on every click, including:
    - Port scanning (both mixed ALLOWED/BLOCKED and purely BLOCKED)
    - Repeated login attempts (Web brute force [ALLOWED], SSH/RDP/DB brute force [BLOCKED])
    - Unauthorized access (DMZ lateral movement, Student-to-Admin access, Web exploit)
    - Multi-stage cyber intrusions (mix of allowed recon, blocked probes, and IDS alerts)
    """
    pattern_choice = random.choice([
        "port_scan_dmz",
        "port_scan_internal",
        "web_brute_force",
        "ssh_brute_force",
        "rdp_brute_force",
        "db_brute_force",
        "unauthorized_dmz_lateral",
        "unauthorized_student_admin",
        "unauthorized_web_exploit",
        "traffic_frequency_burst",
        "multistage_attack"
    ])

    events = []

    if pattern_choice == "port_scan_dmz":
        src = random.choice(["Student Lab", "Faculty"])
        dst = "Public Web Server / DMZ"
        allowed_ports = [80, 443]
        probed_blocked = random.sample([21, 22, 23, 25, 110, 135, 139, 445, 1433, 3306, 3389, 8080], 4)
        ports = allowed_ports + probed_blocked
        random.shuffle(ports)

        for idx, port in enumerate(ports):
            proto = "tcp"
            decision, reason = firewall_decision_detailed(src, dst, port, proto)
            attack = "port_scan" if idx >= 4 else None
            alerts = ids_check(src, dst, port, proto, attack_type=attack)
            severity = assign_severity(alerts, decision)
            log_event(src, dst, port, proto, decision, alerts, reason=reason, severity=severity)
            events.append({
                "source": src,
                "destination": dst,
                "port": port,
                "protocol": proto,
                "decision": decision,
                "reason": reason,
                "alerts": alerts,
                "severity": severity
            })

    elif pattern_choice == "port_scan_internal":
        src = "Student Lab"
        dst = random.choice(["Faculty", "Administration"])
        ports = random.sample([21, 22, 23, 25, 80, 135, 139, 445, 1433, 3306, 3389, 8080], 5)

        for idx, port in enumerate(ports):
            proto = "tcp"
            decision, reason = firewall_decision_detailed(src, dst, port, proto)
            attack = "port_scan" if idx >= 4 else None
            alerts = ids_check(src, dst, port, proto, attack_type=attack)
            severity = assign_severity(alerts, decision)
            log_event(src, dst, port, proto, decision, alerts, reason=reason, severity=severity)
            events.append({
                "source": src,
                "destination": dst,
                "port": port,
                "protocol": proto,
                "decision": decision,
                "reason": reason,
                "alerts": alerts,
                "severity": severity
            })

    elif pattern_choice == "web_brute_force":
        src = random.choice(["Student Lab", "Faculty"])
        dst = "Public Web Server / DMZ"
        port = random.choice([80, 443])
        proto = "tcp"
        count = random.choice([3, 4])

        for i in range(count):
            decision, reason = firewall_decision_detailed(src, dst, port, proto)
            alerts = []
            if i >= 2:
                alerts = ids_check(src, dst, port, proto, attack_type="web_login_brute_force")
            severity = assign_severity(alerts, decision)
            log_event(src, dst, port, proto, decision, alerts, reason=reason, severity=severity)
            events.append({
                "source": src,
                "destination": dst,
                "port": port,
                "protocol": proto,
                "decision": decision,
                "reason": reason,
                "alerts": alerts,
                "severity": severity
            })

    elif pattern_choice == "ssh_brute_force":
        src = "Student Lab"
        dst = random.choice(["Faculty", "Administration"])
        port = 22
        proto = "tcp"
        count = 3

        for _ in range(count):
            decision, reason = firewall_decision_detailed(src, dst, port, proto)
            alerts = ids_check(src, dst, port, proto)
            severity = assign_severity(alerts, decision)
            log_event(src, dst, port, proto, decision, alerts, reason=reason, severity=severity)
            events.append({
                "source": src,
                "destination": dst,
                "port": port,
                "protocol": proto,
                "decision": decision,
                "reason": reason,
                "alerts": alerts,
                "severity": severity
            })

    elif pattern_choice == "rdp_brute_force":
        src = random.choice(["Student Lab", "Public Web Server / DMZ"])
        dst = random.choice(["Administration", "Faculty"])
        if src == dst:
            dst = "Administration"
        port = 3389
        proto = "tcp"
        count = 3

        for i in range(count):
            decision, reason = firewall_decision_detailed(src, dst, port, proto)
            alerts = []
            if i >= 2:
                alerts = ids_check(src, dst, port, proto, attack_type="rdp_brute_force")
            severity = assign_severity(alerts, decision)
            log_event(src, dst, port, proto, decision, alerts, reason=reason, severity=severity)
            events.append({
                "source": src,
                "destination": dst,
                "port": port,
                "protocol": proto,
                "decision": decision,
                "reason": reason,
                "alerts": alerts,
                "severity": severity
            })

    elif pattern_choice == "db_brute_force":
        src = "Student Lab"
        dst = "Administration"
        port = random.choice([1433, 3306])
        proto = "tcp"
        count = 3

        for i in range(count):
            decision, reason = firewall_decision_detailed(src, dst, port, proto)
            alerts = []
            if i >= 2:
                alerts = ids_check(src, dst, port, proto, attack_type="db_brute_force")
            else:
                alerts = ids_check(src, dst, port, proto)
            severity = assign_severity(alerts, decision)
            log_event(src, dst, port, proto, decision, alerts, reason=reason, severity=severity)
            events.append({
                "source": src,
                "destination": dst,
                "port": port,
                "protocol": proto,
                "decision": decision,
                "reason": reason,
                "alerts": alerts,
                "severity": severity
            })

    elif pattern_choice == "unauthorized_dmz_lateral":
        src = "Public Web Server / DMZ"
        dst = random.choice(["Administration", "Faculty", "Student Lab"])
        ports = random.sample([22, 135, 445, 1433, 3389], k=random.choice([2, 3]))

        for port in ports:
            proto = "tcp"
            decision, reason = firewall_decision_detailed(src, dst, port, proto)
            alerts = ids_check(src, dst, port, proto)
            severity = assign_severity(alerts, decision)
            log_event(src, dst, port, proto, decision, alerts, reason=reason, severity=severity)
            events.append({
                "source": src,
                "destination": dst,
                "port": port,
                "protocol": proto,
                "decision": decision,
                "reason": reason,
                "alerts": alerts,
                "severity": severity
            })

    elif pattern_choice == "unauthorized_student_admin":
        src = "Student Lab"
        dst = "Administration"
        ports = random.sample([1433, 3306, 445, 8080, 22], k=random.choice([2, 3]))

        for port in ports:
            proto = "tcp"
            decision, reason = firewall_decision_detailed(src, dst, port, proto)
            alerts = ids_check(src, dst, port, proto)
            severity = assign_severity(alerts, decision)
            log_event(src, dst, port, proto, decision, alerts, reason=reason, severity=severity)
            events.append({
                "source": src,
                "destination": dst,
                "port": port,
                "protocol": proto,
                "decision": decision,
                "reason": reason,
                "alerts": alerts,
                "severity": severity
            })

    elif pattern_choice == "unauthorized_web_exploit":
        src = random.choice(["Student Lab", "Faculty"])
        dst = "Public Web Server / DMZ"
        port = random.choice([80, 443])
        proto = "tcp"

        # 1. Normal allowed web request
        dec1, r1 = firewall_decision_detailed(src, dst, port, proto)
        log_event(src, dst, port, proto, dec1, [], reason=r1, severity="SAFE")
        events.append({
            "source": src, "destination": dst, "port": port, "protocol": proto,
            "decision": dec1, "reason": r1, "alerts": [], "severity": "SAFE"
        })

        # 2. Unauthorized exploit attempt on allowed port
        dec2, r2 = firewall_decision_detailed(src, dst, port, proto)
        alerts2 = ids_check(src, dst, port, proto, attack_type="web_exploit")
        sev2 = assign_severity(alerts2, dec2)
        log_event(src, dst, port, proto, dec2, alerts2, reason=r2, severity=sev2)
        events.append({
            "source": src, "destination": dst, "port": port, "protocol": proto,
            "decision": dec2, "reason": r2, "alerts": alerts2, "severity": sev2
        })

    elif pattern_choice == "traffic_frequency_burst":
        src = random.choice(["Student Lab", "Public Web Server / DMZ"])
        dst = random.choice(["Faculty", "Administration", "Public Web Server / DMZ"])
        if src == dst:
            dst = "Public Web Server / DMZ"
        port = random.choice([80, 443, 8080, 22])
        for _ in range(random.choice([7, 9])):
            dec, rsn = firewall_decision_detailed(src, dst, port, "tcp")
            alr = ids_check(src, dst, port, "tcp", attack_type="traffic_frequency")
            sev = assign_severity(alr, dec)
            log_event(src, dst, port, "tcp", dec, alr, reason=rsn, severity=sev)
            events.append({
                "source": src, "destination": dst, "port": port, "protocol": "tcp",
                "decision": dec, "reason": rsn, "alerts": alr, "severity": sev
            })

    else:  # multistage_attack
        src = "Student Lab"
        # Step 1: Allowed web access
        p1 = random.choice([80, 443])
        dec1, r1 = firewall_decision_detailed(src, "Public Web Server / DMZ", p1, "tcp")
        log_event(src, "Public Web Server / DMZ", p1, "tcp", dec1, [], reason=r1, severity="SAFE")
        events.append({
            "source": src, "destination": "Public Web Server / DMZ", "port": p1,
            "protocol": "tcp", "decision": dec1, "reason": r1, "alerts": [], "severity": "SAFE"
        })

        # Step 2: Blocked probe
        p2 = random.choice([8080, 8443, 21])
        dec2, r2 = firewall_decision_detailed(src, "Public Web Server / DMZ", p2, "tcp")
        log_event(src, "Public Web Server / DMZ", p2, "tcp", dec2, [], reason=r2, severity="LOW")
        events.append({
            "source": src, "destination": "Public Web Server / DMZ", "port": p2,
            "protocol": "tcp", "decision": dec2, "reason": r2, "alerts": [], "severity": "LOW"
        })

        # Step 3: Unauthorized admin access
        p3 = random.choice([1433, 445, 3306])
        dec3, r3 = firewall_decision_detailed(src, "Administration", p3, "tcp")
        alerts3 = ids_check(src, "Administration", p3, "tcp")
        sev3 = assign_severity(alerts3, dec3)
        log_event(src, "Administration", p3, "tcp", dec3, alerts3, reason=r3, severity=sev3)
        events.append({
            "source": src, "destination": "Administration", "port": p3,
            "protocol": "tcp", "decision": dec3, "reason": r3, "alerts": alerts3, "severity": sev3
        })

        # Step 4: Lateral movement from DMZ
        src4 = "Public Web Server / DMZ"
        p4 = 22
        dec4, r4 = firewall_decision_detailed(src4, "Faculty", p4, "tcp")
        alerts4 = ids_check(src4, "Faculty", p4, "tcp")
        sev4 = assign_severity(alerts4, dec4)
        log_event(src4, "Faculty", p4, "tcp", dec4, alerts4, reason=r4, severity=sev4)
        events.append({
            "source": src4, "destination": "Faculty", "port": p4,
            "protocol": "tcp", "decision": dec4, "reason": r4, "alerts": alerts4, "severity": sev4
        })

    return pattern_choice, events


# ---------------- STATISTICS AND METRICS ----------------

def get_platform_statistics():
    """
    Computes all statistics and analytics directly from SQLite database.
    Guarantees no disconnected or fake numbers.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM events")
    total_traffic = cur.fetchone()[0] or 0

    cur.execute("SELECT COUNT(*) FROM events WHERE LOWER(decision) IN ('allow', 'allowed')")
    allowed_count = cur.fetchone()[0] or 0

    cur.execute("SELECT COUNT(*) FROM events WHERE LOWER(decision) IN ('deny', 'blocked')")
    blocked_count = cur.fetchone()[0] or 0

    cur.execute("SELECT COUNT(*) FROM events WHERE alerts != '[]' AND alerts != '' AND alerts IS NOT NULL")
    alerts_count = cur.fetchone()[0] or 0

    # Severity distribution
    cur.execute("SELECT severity, COUNT(*) FROM events GROUP BY severity")
    severity_map = {row[0]: row[1] for row in cur.fetchall()}

    # Recent 20 events for threat posture
    cur.execute("SELECT severity FROM events ORDER BY id DESC LIMIT 20")
    recent_sevs = [r[0] for r in cur.fetchall()]

    if "CRITICAL" in recent_sevs:
        threat_level = "CRITICAL"
        threat_score = 92
        threat_class = "threat-critical"
    elif recent_sevs.count("HIGH") >= 2:
        threat_level = "HIGH"
        threat_score = 75
        threat_class = "threat-high"
    elif recent_sevs.count("MEDIUM") >= 2 or recent_sevs.count("HIGH") == 1:
        threat_level = "ELEVATED"
        threat_score = 48
        threat_class = "threat-elevated"
    else:
        threat_level = "NORMAL"
        threat_score = 12
        threat_class = "threat-normal"

    # Top talkers: source zones
    cur.execute("SELECT source, COUNT(*) as cnt FROM events GROUP BY source ORDER BY cnt DESC LIMIT 5")
    top_sources = [{"zone": r[0], "count": r[1]} for r in cur.fetchall()]

    # Top talkers: destination zones
    cur.execute("SELECT destination, COUNT(*) as cnt FROM events GROUP BY destination ORDER BY cnt DESC LIMIT 5")
    top_destinations = [{"zone": r[0], "count": r[1]} for r in cur.fetchall()]

    # Attack category breakdown
    cur.execute("SELECT alerts FROM events WHERE alerts != '[]' AND alerts != '' AND alerts IS NOT NULL")
    attack_counts = defaultdict(int)
    for (alerts_json,) in cur.fetchall():
        try:
            alerts_list = json.loads(alerts_json)
            for a in alerts_list:
                if "Port Scan" in a:
                    attack_counts["Port Scanning"] += 1
                elif "SSH" in a:
                    attack_counts["SSH Brute Force"] += 1
                elif "HTTP" in a or "Web" in a:
                    attack_counts["Web Attacks"] += 1
                elif "RDP" in a:
                    attack_counts["RDP Brute Force"] += 1
                elif "Database" in a:
                    attack_counts["Database Attacks"] += 1
                elif "Lateral Movement" in a or "DMZ" in a:
                    attack_counts["DMZ Lateral Movement"] += 1
                elif "Administration" in a:
                    attack_counts["Admin Zone Access"] += 1
                elif "Frequency" in a or "Burst" in a:
                    attack_counts["Traffic Anomaly / Burst"] += 1
                elif "Suspicious Port" in a:
                    attack_counts["Suspicious Port Probe"] += 1
                else:
                    attack_counts["Policy Violations"] += 1
        except Exception:
            pass

    # Timeline points: last 20 events
    cur.execute("""
        SELECT timestamp, decision, severity 
        FROM events 
        ORDER BY id DESC LIMIT 20
    """)
    timeline_rows = cur.fetchall()
    timeline = []
    for r in reversed(timeline_rows):
        time_short = r[0].split("T")[1][:8] if "T" in r[0] else r[0][-8:]
        timeline.append({
            "time": time_short,
            "decision": r[1],
            "severity": r[2]
        })

    # Active rules count
    cur.execute("SELECT COUNT(*) FROM firewall_rules WHERE enabled = 1")
    active_rules_count = cur.fetchone()[0] or 0

    conn.close()

    allowed_pct = round((allowed_count / total_traffic * 100), 1) if total_traffic > 0 else 0.0
    blocked_pct = round((blocked_count / total_traffic * 100), 1) if total_traffic > 0 else 0.0

    return {
        "total_traffic": total_traffic,
        "allowed_count": allowed_count,
        "blocked_count": blocked_count,
        "allowed_pct": allowed_pct,
        "blocked_pct": blocked_pct,
        "alerts_count": alerts_count,
        "threat_level": threat_level,
        "threat_score": threat_score,
        "threat_class": threat_class,
        "firewall_status": "Active (Enforcing)",
        "ids_status": "Active (Deep Packet Simulation)",
        "active_rules_count": active_rules_count,
        "severity_breakdown": {
            "CRITICAL": severity_map.get("CRITICAL", 0),
            "HIGH": severity_map.get("HIGH", 0),
            "MEDIUM": severity_map.get("MEDIUM", 0),
            "LOW": severity_map.get("LOW", 0),
            "SAFE": severity_map.get("SAFE", 0)
        },
        "attack_distribution": dict(attack_counts),
        "top_sources": top_sources,
        "top_destinations": top_destinations,
        "timeline": timeline
    }


# ---------------- PAGE ROUTES ----------------

@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    stats = get_platform_statistics()
    is_admin = session.get("logged_in", False)
    return render_template("dashboard.html", zones=ZONES, stats=stats, is_admin=is_admin)


@app.route("/simulation")
def simulation():
    is_admin = session.get("logged_in", False)
    return render_template("simulation.html", zones=ZONES, is_admin=is_admin)


@app.route("/analytics")
def analytics():
    stats = get_platform_statistics()
    is_admin = session.get("logged_in", False)
    return render_template("analytics.html", zones=ZONES, stats=stats, is_admin=is_admin)


@app.route("/rules")
def rules_page():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()
    cur.execute("SELECT id, priority, name, source, destination, port, protocol, action, enabled, description FROM firewall_rules ORDER BY priority ASC")
    rules = [
        {
            "id": r[0], "priority": r[1], "name": r[2], "source": r[3],
            "destination": r[4], "port": r[5], "protocol": r[6], "action": r[7],
            "enabled": bool(r[8]), "description": r[9]
        }
        for r in cur.fetchall()
    ]
    conn.close()
    is_admin = session.get("logged_in", False)
    return render_template("rules.html", rules=rules, zones=ZONES, is_admin=is_admin)


@app.route("/settings")
def settings_page():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()
    cur.execute("SELECT key, value FROM system_settings")
    settings = {r[0]: r[1] for r in cur.fetchall()}
    conn.close()
    is_admin = session.get("logged_in", False)
    return render_template("settings.html", settings=settings, is_admin=is_admin)


@app.route("/report")
def report_page():
    stats = get_platform_statistics()
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()
    cur.execute("""
        SELECT timestamp, source, destination, port, protocol, decision, alerts, severity, decision_reason 
        FROM events 
        ORDER BY id DESC LIMIT 25
    """)
    recent = [
        {
            "timestamp": r[0], "source": r[1], "destination": r[2], "port": r[3],
            "protocol": r[4], "decision": r[5], "alerts": json.loads(r[6] or "[]"),
            "severity": r[7], "reason": r[8]
        }
        for r in cur.fetchall()
    ]
    conn.close()
    is_admin = session.get("logged_in", False)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return render_template("report.html", stats=stats, recent=recent, now_str=now_str, is_admin=is_admin)


# ---------------- AUTHENTICATION ----------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        # Default credentials for College Network Security Platform
        if username == "admin" and password == "admin123":
            session["logged_in"] = True
            session["username"] = "admin"
            session["role"] = "Security Administrator"
            flash("Welcome back, Security Administrator.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid administrator credentials. Try admin / admin123.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("dashboard"))


# ---------------- API: SIMULATION & TRAFFIC ----------------

@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    data = request.get_json(silent=True) or {}

    src = data.get("source")
    dst = data.get("destination")
    port = data.get("port")
    protocol = data.get("protocol", "tcp")

    if src not in ZONES or dst not in ZONES:
        return jsonify({"error": "Invalid network zone"}), 400

    try:
        port = int(port)
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid port"}), 400

    if not 1 <= port <= 65535:
        return jsonify({"error": "Invalid port"}), 400

    if str(protocol).lower() not in ("tcp", "udp"):
        return jsonify({"error": "Invalid protocol"}), 400

    decision, reason = firewall_decision_detailed(src, dst, port, protocol)
    alerts = ids_check(src, dst, port, protocol)
    severity = assign_severity(alerts, decision)

    log_event(src, dst, port, protocol, decision, alerts, reason=reason, severity=severity)

    return jsonify({
        "source": src,
        "destination": dst,
        "port": port,
        "protocol": protocol,
        "decision": decision,
        "reason": reason,
        "alerts": alerts,
        "severity": severity
    })


@app.route("/api/generate_safe", methods=["POST"])
def api_generate_safe():
    zones = list(ZONES.keys())

    if random.random() < 0.7:
        src = dst = random.choice(zones)
        port = random.choice([22, 80, 443])
    else:
        src = random.choice(zones)
        dst = "Public Web Server / DMZ"
        port = random.choice([80, 443])

    protocol = "tcp"

    decision, reason = firewall_decision_detailed(src, dst, port, protocol)
    alerts = ids_check(src, dst, port, protocol)
    severity = assign_severity(alerts, decision)

    log_event(src, dst, port, protocol, decision, alerts, reason=reason, severity=severity)

    return jsonify({
        "source": src,
        "destination": dst,
        "port": port,
        "protocol": protocol,
        "decision": decision,
        "reason": reason,
        "alerts": alerts,
        "severity": severity
    })


@app.route("/api/generate_suspicious", methods=["POST"])
def api_generate_suspicious():
    pattern_name, result = generate_suspicious_traffic()

    all_alerts = []
    for ev in result:
        for alert in ev.get("alerts", []):
            if alert not in all_alerts:
                all_alerts.append(alert)

    return jsonify({
        "status": "completed",
        "pattern": pattern_name,
        "events": result,
        "alerts": all_alerts
    })


@app.route("/api/generate_traffic_stream", methods=["POST"])
def api_generate_traffic_stream():
    """Generates a burst of realistic mixed safe and suspicious campus network packets."""
    generated = []
    # 3-5 Safe packets
    for _ in range(random.randint(3, 5)):
        zones = list(ZONES.keys())
        if random.random() < 0.6:
            src = dst = random.choice(zones)
            port = random.choice([80, 443, 22])
        else:
            src = random.choice(["Student Lab", "Faculty"])
            dst = "Public Web Server / DMZ"
            port = random.choice([80, 443])
        dec, rsn = firewall_decision_detailed(src, dst, port, "tcp")
        alr = ids_check(src, dst, port, "tcp")
        sev = assign_severity(alr, dec)
        log_event(src, dst, port, "tcp", dec, alr, reason=rsn, severity=sev)
        generated.append({"source": src, "destination": dst, "port": port, "decision": dec, "alerts": alr, "severity": sev})

    # 1 Suspicious pattern
    _, susp_events = generate_suspicious_traffic()
    generated.extend(susp_events)

    return jsonify({
        "status": "success",
        "generated_count": len(generated),
        "events": generated
    })


# ---------------- API: TELEMETRY & DATA ----------------

@app.route("/api/events")
def api_events():
    limit = request.args.get("limit", 100, type=int)
    severity_filter = request.args.get("severity", None)
    decision_filter = request.args.get("decision", None)
    search_query = request.args.get("search", None)

    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()

    query = """
        SELECT timestamp, source, destination, port,
        protocol, decision, alerts, decision_reason, severity, id
        FROM events
        WHERE 1=1
    """
    params = []

    if severity_filter and severity_filter.upper() != "ALL":
        query += " AND UPPER(severity) = ?"
        params.append(severity_filter.upper())

    if decision_filter and decision_filter.upper() != "ALL":
        if decision_filter.upper() == "ALLOWED":
            query += " AND LOWER(decision) IN ('allow', 'allowed')"
        elif decision_filter.upper() == "BLOCKED":
            query += " AND LOWER(decision) IN ('deny', 'blocked')"

    if search_query:
        query += " AND (source LIKE ? OR destination LIKE ? OR alerts LIKE ? OR decision_reason LIKE ?)"
        s = f"%{search_query}%"
        params.extend([s, s, s, s])

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()

    events = []
    for row in rows:
        events.append({
            "id": row[9],
            "timestamp": row[0],
            "source": row[1],
            "destination": row[2],
            "port": row[3],
            "protocol": row[4],
            "decision": row[5],
            "alerts": json.loads(row[6] or "[]"),
            "reason": row[7] or "Firewall Policy Evaluation",
            "severity": row[8] or "LOW"
        })

    return jsonify(events)


@app.route("/api/stats")
def api_stats():
    return jsonify(get_platform_statistics())


@app.route("/api/topology")
def api_topology():
    return jsonify({
        "zones": ZONES,
        "firewall": "Firewall"
    })


@app.route("/api/export_csv")
def api_export_csv():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()
    cur.execute("""
        SELECT id, timestamp, source, destination, port, protocol, decision, decision_reason, alerts, severity
        FROM events
        ORDER BY id DESC
    """)
    rows = cur.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Event ID", "Timestamp (UTC)", "Source Zone", "Destination Zone",
        "Port", "Protocol", "Decision", "Firewall Rule/Reason", "IDS Alerts", "Severity"
    ])
    for r in rows:
        alerts_list = json.loads(r[8] or "[]")
        writer.writerow([
            r[0], r[1], r[2], r[3], r[4], str(r[5]).upper(),
            str(r[6]).upper(), r[7], ", ".join(alerts_list) if alerts_list else "None", r[9]
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=college_security_event_log.csv"}
    )


# ---------------- API: RULES MANAGEMENT ----------------

@app.route("/api/rules", methods=["GET", "POST"])
def api_rules():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        prio = data.get("priority", 90)
        name = data.get("name", "Custom Rule").strip()
        src = data.get("source", "ANY").strip()
        dst = data.get("destination", "ANY").strip()
        port = data.get("port", "*").strip()
        proto = data.get("protocol", "ANY").strip().upper()
        act = data.get("action", "deny").strip().lower()
        desc = data.get("description", "").strip()

        if not name:
            return jsonify({"error": "Rule name is required"}), 400

        cur.execute("""
            INSERT INTO firewall_rules (priority, name, source, destination, port, protocol, action, enabled, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
        """, (prio, name, src, dst, port, proto, act, desc))
        conn.commit()
        rule_id = cur.lastrowid
        conn.close()
        return jsonify({"status": "created", "rule_id": rule_id}), 201

    cur.execute("SELECT id, priority, name, source, destination, port, protocol, action, enabled, description FROM firewall_rules ORDER BY priority ASC")
    rules = [
        {
            "id": r[0], "priority": r[1], "name": r[2], "source": r[3],
            "destination": r[4], "port": r[5], "protocol": r[6], "action": r[7],
            "enabled": bool(r[8]), "description": r[9]
        }
        for r in cur.fetchall()
    ]
    conn.close()
    return jsonify(rules)


@app.route("/api/rules/<int:rule_id>/toggle", methods=["POST"])
def api_toggle_rule(rule_id):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()
    cur.execute("SELECT enabled FROM firewall_rules WHERE id = ?", (rule_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Rule not found"}), 404

    new_val = 0 if row[0] == 1 else 1
    cur.execute("UPDATE firewall_rules SET enabled = ? WHERE id = ?", (new_val, rule_id))
    conn.commit()
    conn.close()
    return jsonify({"status": "toggled", "rule_id": rule_id, "enabled": bool(new_val)})


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
def api_delete_rule(rule_id):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("DELETE FROM firewall_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "rule_id": rule_id})


@app.route("/api/rules/reset", methods=["POST"])
def api_reset_rules():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("DELETE FROM firewall_rules")
    seed_default_rules(conn)
    conn.commit()
    conn.close()
    return jsonify({"status": "reset_to_defaults"})


# ---------------- API: SETTINGS ----------------

@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()

    if request.method == "POST":
        data = request.get_json(silent=True) or request.form.to_dict() or {}
        for k, v in data.items():
            cur.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)", (k, str(v)))
        conn.commit()
        conn.close()
        return jsonify({"status": "saved"})

    cur.execute("SELECT key, value FROM system_settings")
    settings = {r[0]: r[1] for r in cur.fetchall()}
    conn.close()
    return jsonify(settings)


# ---------------- API: CLEAR LOGS / RESET ----------------

@app.route("/api/clear_logs", methods=["POST"])
@app.route("/api/reset", methods=["GET", "POST"])
def api_clear_logs():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("DELETE FROM events")
    conn.commit()
    conn.close()

    ssh_attempts.clear()
    port_scans.clear()
    rdp_attempts.clear()
    login_attempts.clear()
    zone_request_times.clear()

    return jsonify({"status": "cleared"})


# ---------------- START APPLICATION ----------------

if __name__ == "__main__":
    init_db()

    print("==================================================================")
    print("  CAMPUS SECURE: Next-Gen Network Security & SOC Platform Active  ")
    print("  Firewall Policy Engine:  [ACTIVE - Rule-Based Enforcement]")
    print("  Intrusion Detection:    [ACTIVE - Multi-Vector Inspection]")
    print("  SQLite Persistence:     [CONNECTED - Events, Rules, Settings]")
    print("  SOC Interface:          http://127.0.0.1:5000/dashboard")
    print("==================================================================")

    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
