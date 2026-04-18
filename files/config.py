# =============================================================================
# config.py — Central configuration for Network Audit Tool
# =============================================================================

# ── Target ────────────────────────────────────────────────────────────────────
TARGET_NETWORK     = "10.0.2.0/24"   # Your home/lab network range
CAPTURE_INTERFACE  = None               # None = auto-detect
CAPTURE_DURATION   = 120                # Seconds to capture traffic

# ── Output paths ──────────────────────────────────────────────────────────────
NMAP_OUTPUT_FILE  = "data/nmap_output.xml"
PCAP_OUTPUT_FILE  = "data/capture.pcap"
FINDINGS_FILE     = "data/findings.json"
REPORTS_DIR       = "reports/"

# ── Nmap scan options ─────────────────────────────────────────────────────────
NMAP_ARGUMENTS = "-sV -sC -O --open -T4"

# ── Risky ports ───────────────────────────────────────────────────────────────
RISKY_PORTS = {
    21:   {"name": "FTP",       "risk": "Plaintext file transfer — credentials exposed"},
    23:   {"name": "Telnet",    "risk": "Plaintext remote access — credentials exposed"},
    25:   {"name": "SMTP",      "risk": "Mail relay — potential spam/abuse vector"},
    53:   {"name": "DNS",       "risk": "DNS exposed — zone transfer or amplification risk"},
    80:   {"name": "HTTP",      "risk": "Unencrypted web traffic — data interception risk"},
    110:  {"name": "POP3",      "risk": "Plaintext email retrieval"},
    135:  {"name": "RPC",       "risk": "Windows RPC — exploitation vector"},
    139:  {"name": "NetBIOS",   "risk": "Legacy Windows sharing — credential exposure"},
    445:  {"name": "SMB",       "risk": "EternalBlue / ransomware vector — restrict immediately"},
    1433: {"name": "MSSQL",     "risk": "Database port exposed — brute force / SQLi risk"},
    3306: {"name": "MySQL",     "risk": "Database port exposed — restrict to localhost"},
    3389: {"name": "RDP",       "risk": "Remote Desktop exposed — brute force / BlueKeep risk"},
    5900: {"name": "VNC",       "risk": "Remote desktop — often weakly authenticated"},
    8080: {"name": "HTTP-Alt",  "risk": "Alternate HTTP — often misconfigured dev servers"},
}

# ── CVSS v3.1 severity mapping ────────────────────────────────────────────────
CVSS_MAP = {
    "telnet_open":        {"score": 9.1, "label": "Critical"},
    "ftp_open":           {"score": 7.5, "label": "High"},
    "smb_open":           {"score": 8.8, "label": "High"},
    "rdp_open":           {"score": 8.8, "label": "High"},
    "vnc_open":           {"score": 7.2, "label": "High"},
    "mssql_open":         {"score": 7.5, "label": "High"},
    "mysql_open":         {"score": 7.5, "label": "High"},
    "http_open":          {"score": 5.3, "label": "Medium"},
    "http_alt_open":      {"score": 5.3, "label": "Medium"},
    "rpc_open":           {"score": 6.5, "label": "Medium"},
    "netbios_open":       {"score": 6.5, "label": "Medium"},
    "smtp_open":          {"score": 5.3, "label": "Medium"},
    "dns_open":           {"score": 5.3, "label": "Medium"},
    "no_hostname":        {"score": 2.5, "label": "Low"},
    "plaintext_ftp":      {"score": 7.5, "label": "High"},
    "plaintext_telnet":   {"score": 9.1, "label": "Critical"},
    "plaintext_http":     {"score": 5.3, "label": "Medium"},
    "arp_anomaly":        {"score": 8.0, "label": "High"},
    "generic_risky_port": {"score": 5.0, "label": "Medium"},
}

# ── Severity colours (R, G, B) for PDF report ─────────────────────────────────
SEVERITY_COLORS = {
    "Critical": (220, 50,  50),
    "High":     (230, 110, 30),
    "Medium":   (200, 165, 20),
    "Low":      (40,  150, 80),
    "Info":     (60,  120, 200),
}

# ── Report metadata ────────────────────────────────────────────────────────────
ASSESSOR_NAME   = "godfrey"
ASSESSOR_TOOL   = "Network Audit Tool v1.0"
REPORT_CLASSIFY = "CONFIDENTIAL"
