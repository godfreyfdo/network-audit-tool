TARGET_NETWORK     = "10.0.2.0/24"
CAPTURE_INTERFACE  = None
CAPTURE_DURATION   = 120
NMAP_OUTPUT_FILE   = "data/nmap_output.xml"
PCAP_OUTPUT_FILE   = "data/capture.pcap"
FINDINGS_FILE      = "data/findings.json"
REPORTS_DIR        = "reports/"
NMAP_ARGUMENTS     = "-sV -sC -O --open -T4"

RISKY_PORTS = {
    21:   {"name": "FTP",      "risk": "Plaintext file transfer"},
    23:   {"name": "Telnet",   "risk": "Plaintext remote access"},
    25:   {"name": "SMTP",     "risk": "Mail relay abuse vector"},
    53:   {"name": "DNS",      "risk": "Zone transfer / amplification"},
    80:   {"name": "HTTP",     "risk": "Unencrypted web traffic"},
    110:  {"name": "POP3",     "risk": "Plaintext email retrieval"},
    135:  {"name": "RPC",      "risk": "Windows RPC exploitation"},
    139:  {"name": "NetBIOS",  "risk": "Legacy Windows sharing"},
    445:  {"name": "SMB",      "risk": "EternalBlue / ransomware vector"},
    1433: {"name": "MSSQL",    "risk": "Database port exposed"},
    3306: {"name": "MySQL",    "risk": "Database port exposed"},
    3389: {"name": "RDP",      "risk": "Brute force / BlueKeep risk"},
    5900: {"name": "VNC",      "risk": "Weakly authenticated desktop"},
    8080: {"name": "HTTP-Alt", "risk": "Misconfigured dev server"},
}

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

SEVERITY_COLORS = {
    "Critical": (220, 50,  50),
    "High":     (230, 110, 30),
    "Medium":   (200, 165, 20),
    "Low":      (40,  150, 80),
    "Info":     (60,  120, 200),
}

ASSESSOR_NAME   = "Johannez"
ASSESSOR_TOOL   = "Network Audit Tool v1.0"
REPORT_CLASSIFY = "CONFIDENTIAL"
