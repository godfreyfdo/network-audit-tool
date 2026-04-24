"""
report/report_generator.py
Generates a professional VAPT-style PDF network audit report using fpdf2.
Reads from data/findings.json (CVSS-scored) and data/nmap_output.xml (host info).
"""

import json
import os
from datetime import datetime
from fpdf import FPDF
from fpdf.enums import XPos, YPos

# ─── Config ───────────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "Critical": (220, 50,  50),
    "High":     (220, 100, 30),
    "Medium":   (220, 160, 30),
    "Low":      (50,  130, 220),
    "Info":     (100, 100, 100),
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

BRAND = {
    "name":    "Network Audit Tool",
    "version": "v1.0",
    "org":     "Godfrey Fernandes",
    "primary": (30, 60, 120),      # dark navy
    "accent":  (0,  160, 200),     # teal
    "bg_alt":  (245, 247, 252),    # light grey row
}


# ─── PDF Class ────────────────────────────────────────────────────────────────

class AuditReport(FPDF):

    def __init__(self, target: str, scan_time: str):
        super().__init__()
        self.target = target
        self.scan_time = scan_time
        self.set_auto_page_break(auto=True, margin=20)
        self.add_page()

    # ── Header / Footer ──────────────────────────────────────────────────────

    def header(self):
        if self.page_no() == 1:
            return  # cover page handles itself
        r, g, b = BRAND["primary"]
        self.set_fill_color(r, g, b)
        self.rect(0, 0, 210, 12, "F")
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 8)
        self.set_xy(10, 3)
        self.cell(0, 6, f"Network Security Audit Report  |  Target: {self.target}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)
        self.set_y(16)

    def footer(self):
        self.set_y(-14)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(150, 150, 150)
        self.cell(0, 5, f"CONFIDENTIAL - {BRAND['org']}  |  Generated {self.scan_time}  |  Page {self.page_no()}", align="C")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def h1(self, text: str):
        r, g, b = BRAND["primary"]
        self.set_font("Helvetica", "B", 14)
        self.set_text_color(r, g, b)
        self.ln(4)
        self.cell(0, 8, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        ar, ag, ab = BRAND["accent"]
        self.set_draw_color(ar, ag, ab)
        self.set_line_width(0.6)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)
        self.set_text_color(0, 0, 0)

    def h2(self, text: str):
        r, g, b = BRAND["primary"]
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(r, g, b)
        self.ln(3)
        self.cell(0, 7, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(0, 0, 0)

    def body(self, text: str):
        self.set_font("Helvetica", "", 9)
        self.set_text_color(50, 50, 50)
        self.multi_cell(0, 5, text)
        self.set_text_color(0, 0, 0)

    def kv(self, key: str, val: str, fill=False):
        """Key-value row."""
        if fill:
            r, g, b = BRAND["bg_alt"]
            self.set_fill_color(r, g, b)
        self.set_font("Helvetica", "B", 9)
        self.cell(50, 6, key, fill=fill)
        self.set_font("Helvetica", "", 9)
        self.cell(0, 6, str(val), fill=fill, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def severity_badge(self, severity: str, x=None, y=None):
        r, g, b = SEVERITY_COLORS.get(severity, (100, 100, 100))
        ox, oy = self.get_x(), self.get_y()
        if x is not None:
            self.set_xy(x, y)
        self.set_fill_color(r, g, b)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 8)
        self.cell(22, 5, severity.upper(), align="C", fill=True)
        self.set_text_color(0, 0, 0)
        if x is not None:
            self.set_xy(ox, oy)

    def table_header(self, cols: list, widths: list):
        r, g, b = BRAND["primary"]
        self.set_fill_color(r, g, b)
        self.set_text_color(255, 255, 255)
        self.set_font("Helvetica", "B", 8)
        for col, w in zip(cols, widths):
            self.cell(w, 7, col, border=0, fill=True, align="C")
        self.ln()
        self.set_text_color(0, 0, 0)

    def table_row(self, vals: list, widths: list, fill=False, aligns=None):
        if aligns is None:
            aligns = ["L"] * len(vals)
        if fill:
            r, g, b = BRAND["bg_alt"]
            self.set_fill_color(r, g, b)
        self.set_font("Helvetica", "", 8)
        for val, w, al in zip(vals, widths, aligns):
            self.cell(w, 6, str(val), border=0, fill=fill, align=al)
        self.ln()


# ─── Builder ──────────────────────────────────────────────────────────────────

def _cover_page(pdf: AuditReport, host_count: int, finding_count: int, severity_counts: dict):
    """Page 1 - styled cover."""
    r, g, b = BRAND["primary"]
    pdf.set_fill_color(r, g, b)
    pdf.rect(0, 0, 210, 80, "F")

    ar, ag, ab = BRAND["accent"]
    pdf.set_fill_color(ar, ag, ab)
    pdf.rect(0, 78, 210, 4, "F")

    pdf.set_xy(0, 20)
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 14, "Network Security", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 14, "Audit Report", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(180, 210, 255)
    pdf.cell(0, 7, f"Target: {pdf.target}", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 7, f"Scan Date: {pdf.scan_time}", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_text_color(0, 0, 0)
    pdf.set_y(95)

    # Summary boxes
    boxes = [
        ("Hosts Found",    str(host_count)),
        ("Findings",       str(finding_count)),
        ("Critical",       str(severity_counts.get("Critical", 0))),
        ("High",           str(severity_counts.get("High", 0))),
        ("Medium",         str(severity_counts.get("Medium", 0))),
    ]
    box_w = 36
    start_x = (210 - box_w * len(boxes)) / 2
    for i, (label, val) in enumerate(boxes):
        bx = start_x + i * box_w
        pdf.set_xy(bx, 95)
        # colour by severity
        if label in SEVERITY_COLORS:
            fr, fg, fb = SEVERITY_COLORS[label]
        else:
            fr, fg, fb = BRAND["accent"]
        pdf.set_fill_color(fr, fg, fb)
        pdf.rect(bx + 2, 95, box_w - 4, 24, "F")
        pdf.set_xy(bx + 2, 96)
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(box_w - 4, 12, val, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_xy(bx + 2, 108)
        pdf.set_font("Helvetica", "", 7)
        pdf.cell(box_w - 4, 5, label, align="C")

    pdf.set_text_color(0, 0, 0)
    pdf.set_y(130)

    # Prepared by block
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 6, f"Prepared by: {BRAND['org']}", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.cell(0, 6, f"Tool: {BRAND['name']} {BRAND['version']}", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(0, 0, 0)


def _executive_summary(pdf: AuditReport, hosts: list, findings: list, severity_counts: dict):
    pdf.add_page()
    pdf.h1("1. Executive Summary")
    pdf.body(
        f"This report presents the findings of an automated network security audit conducted against "
        f"the target range {pdf.target} on {pdf.scan_time}. The scan identified {len(hosts)} active "
        f"host(s) and {len(findings)} security finding(s) across multiple severity levels."
    )
    pdf.ln(3)

    # Severity breakdown table
    pdf.h2("Severity Distribution")
    cols   = ["Severity", "Count", "Action Required"]
    widths = [50, 30, 110]
    action_map = {
        "Critical": "Immediate remediation required - patch or isolate within 24 hours",
        "High":     "Remediate within 7 days - prioritise in next sprint",
        "Medium":   "Remediate within 30 days - schedule in upcoming cycle",
        "Low":      "Address in next maintenance window",
        "Info":     "Review for awareness - no immediate action needed",
    }
    pdf.table_header(cols, widths)
    for i, sev in enumerate(SEVERITY_ORDER):
        count = severity_counts.get(sev, 0)
        if count == 0:
            continue
        pdf.table_row([sev, str(count), action_map[sev]], widths, fill=(i % 2 == 0))

    pdf.ln(4)
    pdf.h2("Scope & Methodology")
    pdf.body(
        "Phase 1 - Nmap active scan (-sV -sC -O --open -T4) to enumerate live hosts, open ports, "
        "running services, and OS fingerprints.\n"
        "Phase 2 - Passive traffic capture (tshark, 60 s) on the primary interface to identify "
        "anomalous protocols and ARP behaviour.\n"
        "Phase 3 - Automated anomaly detection flagging risky ports, cleartext protocols, and "
        "devices lacking reverse DNS.\n"
        "Phase 4 - CVSS v3.1 scoring applied to all findings."
    )


def _host_inventory(pdf: AuditReport, hosts: list):
    pdf.add_page()
    pdf.h1("2. Host Inventory")
    pdf.body(f"Active hosts discovered on {pdf.target}:")
    pdf.ln(2)

    cols   = ["IP Address", "OS (Confidence)", "Open Ports", "Risky Ports", "Risk Level"]
    widths = [28, 60, 52, 22, 28]
    pdf.table_header(cols, widths)
    for i, h in enumerate(hosts):
        ports_str = ", ".join(str(p) for p in h.get("open_ports", []))
        pdf.table_row(
            [h["ip"], h.get("os", "Unknown"), ports_str, str(h.get("risky_count", 0)), h.get("risk_level", "--")],
            widths, fill=(i % 2 == 0), aligns=["L", "L", "L", "C", "C"]
        )


def _findings_detail(pdf: AuditReport, findings: list):
    pdf.add_page()
    pdf.h1("3. Detailed Findings")

    for i, f in enumerate(findings):
        fid       = f.get("id", f"FIND-{i+1:03d}")
        title     = f.get("title", f.get("description", "Finding"))
        severity  = f.get("severity", "Info")
        cvss      = f.get("cvss_score", "N/A")
        ip        = f.get("ip", "--")
        port      = f.get("port", "--")
        service   = f.get("service", "--")
        desc      = f.get("description", title)
        rec       = f.get("recommendation", "Review and remediate.")

        # Check page space
        if pdf.get_y() > 230:
            pdf.add_page()

        # Finding header bar
        r, g, b = SEVERITY_COLORS.get(severity, (100, 100, 100))
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 9)
        pdf.cell(0, 7, f"  {fid}  -  {title}", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_text_color(0, 0, 0)

        # Meta row
        pdf.set_font("Helvetica", "", 8)
        pdf.set_fill_color(*BRAND["bg_alt"])
        pdf.cell(40, 5, f"Severity: {severity}", fill=True)
        pdf.cell(35, 5, f"CVSS: {cvss}", fill=True)
        pdf.cell(40, 5, f"Host: {ip}", fill=True)
        pdf.cell(35, 5, f"Port: {port} / {service}", fill=True)
        pdf.ln(6)

        # Description
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(30, 5, "Description:")
        pdf.ln(5)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_x(14)
        pdf.multi_cell(185, 4.5, desc)

        # Recommendation
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(30, 5, "Recommendation:")
        pdf.ln(5)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_x(14)
        pdf.multi_cell(185, 4.5, rec)
        pdf.ln(4)


def _remediation_table(pdf: AuditReport, findings: list):
    pdf.add_page()
    pdf.h1("4. Remediation Summary")
    pdf.body("Prioritised remediation actions ordered by CVSS score:")
    pdf.ln(2)

    sorted_f = sorted(
        findings,
        key=lambda x: float(x.get("cvss_score", 0)) if str(x.get("cvss_score", "0")).replace(".", "").isdigit() else 0,
        reverse=True
    )

    cols   = ["ID", "Host", "Finding", "CVSS", "Severity", "Action"]
    widths = [20, 25, 50, 14, 20, 61]
    pdf.table_header(cols, widths)
    for i, f in enumerate(sorted_f):
        rec_short = f.get("recommendation", "Remediate")[:55] + ("..." if len(f.get("recommendation", "")) > 55 else "")
        pdf.table_row(
            [f.get("id","--"), f.get("ip","--"), f.get("title", f.get("description",""))[:35],
             str(f.get("cvss_score","--")), f.get("severity","--"), rec_short],
            widths, fill=(i % 2 == 0)
        )


def _appendix(pdf: AuditReport):
    pdf.add_page()
    pdf.h1("5. Appendix")

    pdf.h2("CVSS v3.1 Severity Scale")
    ranges = [
        ("Critical", "9.0 - 10.0", "Exploit easily weaponised; immediate action"),
        ("High",     "7.0 - 8.9",  "Significant risk; patch within 7 days"),
        ("Medium",   "4.0 - 6.9",  "Moderate risk; patch within 30 days"),
        ("Low",      "0.1 - 3.9",  "Minimal risk; address in maintenance window"),
        ("Info",     "0.0",        "Informational - no direct exploit risk"),
    ]
    cols   = ["Severity", "Score Range", "Guidance"]
    widths = [35, 35, 120]
    pdf.table_header(cols, widths)
    for i, (sev, rng, guide) in enumerate(ranges):
        pdf.table_row([sev, rng, guide], widths, fill=(i % 2 == 0))

    pdf.ln(6)
    pdf.h2("Tool Versions")
    tools = [
        ("python-nmap",  "Active host + port discovery (nmap -sV -sC -O --open -T4)"),
        ("pyshark",      "Passive .pcap analysis via tshark"),
        ("fpdf2",        "PDF report generation"),
        ("rich",         "Terminal output formatting"),
        ("netifaces",    "Network interface auto-detection"),
    ]
    cols   = ["Library", "Purpose"]
    widths = [40, 150]
    pdf.table_header(cols, widths)
    for i, (lib, purpose) in enumerate(tools):
        pdf.table_row([lib, purpose], widths, fill=(i % 2 == 0))

    pdf.ln(6)
    pdf.h2("Disclaimer")
    pdf.body(
        "This report was generated by an automated tool for educational and internship portfolio purposes. "
        "Findings should be validated by a qualified security analyst before remediation. "
        "This tool is intended for use only on networks you own or have explicit authorisation to test."
    )


# ─── Main Entry ───────────────────────────────────────────────────────────────

def generate_report(
    findings_path: str = "data/findings.json",
    hosts_data: list = None,
    output_path: str = "reports/network_audit_report.pdf",
    target: str = "10.0.2.0/24",
) -> str:
    """
    Generate PDF report.

    Args:
        findings_path: path to CVSS-scored findings JSON
        hosts_data:    list of host dicts (from nmap_scanner); if None, derived from findings
        output_path:   where to save the PDF
        target:        scan target range string

    Returns:
        Absolute path to generated PDF.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Load findings
    with open(findings_path) as f:
        findings = json.load(f)

    # Derive host list if not provided
    if hosts_data is None:
        seen = {}
        for finding in findings:
            ip = finding.get("ip", "unknown")
            if ip not in seen:
                seen[ip] = {"ip": ip, "os": "Unknown", "open_ports": [], "risky_count": 0, "risk_level": "--"}
        hosts_data = list(seen.values())

    # Severity counts
    severity_counts: dict = {}
    for f in findings:
        sev = f.get("severity", "Info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M")

    pdf = AuditReport(target=target, scan_time=scan_time)

    _cover_page(pdf, len(hosts_data), len(findings), severity_counts)
    _executive_summary(pdf, hosts_data, findings, severity_counts)
    _host_inventory(pdf, hosts_data)
    _findings_detail(pdf, findings)
    _remediation_table(pdf, findings)
    _appendix(pdf)

    pdf.output(output_path)
    return os.path.abspath(output_path)


# ─── Standalone test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Minimal test - uses sample data if real files missing
    SAMPLE_FINDINGS = [
        {
            "id": "FIND-001", "ip": "10.0.2.2", "port": 135, "service": "msrpc",
            "title": "Port 135 (msrpc) Open",
            "description": "Microsoft RPC endpoint mapper is exposed. This service is commonly targeted by worms and RPC-based exploits (e.g. MS03-026).",
            "recommendation": "Restrict port 135 via firewall. Disable DCOM if not required.",
            "severity": "High", "cvss_score": 7.5
        },
        {
            "id": "FIND-002", "ip": "10.0.2.2", "port": 445, "service": "microsoft-ds",
            "title": "Port 445 (SMB) Open",
            "description": "SMB port 445 exposed. Historic target of EternalBlue (MS17-010) and other ransomware campaigns.",
            "recommendation": "Block port 445 at perimeter firewall. Ensure MS17-010 patch applied. Disable SMBv1.",
            "severity": "High", "cvss_score": 8.1
        },
        {
            "id": "FIND-003", "ip": "10.0.2.2", "port": None, "service": None,
            "title": "No Reverse DNS - Possible Rogue Device",
            "description": "Device at 10.0.2.2 has no PTR record. May be unmanaged, rogue, or misconfigured.",
            "recommendation": "Add PTR record or investigate device legitimacy via MAC lookup.",
            "severity": "Low", "cvss_score": 2.1
        },
        {
            "id": "FIND-004", "ip": "10.0.2.3", "port": 53, "service": "domain",
            "title": "Port 53 (DNS) Open - BIND 9.11.4-P2",
            "description": "DNS service running BIND 9.11.4-P2. This version is outdated and has known CVEs including CVE-2019-6477.",
            "recommendation": "Upgrade BIND to latest stable release. Restrict recursive queries to internal clients only.",
            "severity": "Medium", "cvss_score": 5.3
        },
        {
            "id": "FIND-005", "ip": "10.0.2.3", "port": None, "service": None,
            "title": "No Reverse DNS - Possible Rogue Device",
            "description": "Device at 10.0.2.3 has no PTR record. May be unmanaged, rogue, or misconfigured.",
            "recommendation": "Add PTR record or investigate device legitimacy via MAC lookup.",
            "severity": "Low", "cvss_score": 2.1
        },
    ]

    SAMPLE_HOSTS = [
        {"ip": "10.0.2.2", "os": "AT&T BGW210 (93%)", "open_ports": [135, 445, 1042, 1043, 7778], "risky_count": 2, "risk_level": "Medium"},
        {"ip": "10.0.2.3", "os": "AT&T BGW210 (91%)", "open_ports": [53], "risky_count": 1, "risk_level": "Medium"},
    ]

    import sys, pathlib
    # Try real findings first
    findings_file = "data/findings.json"
    if not pathlib.Path(findings_file).exists():
        print("[!] data/findings.json not found - using sample data for demo.")
        import tempfile, json as _json
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        _json.dump(SAMPLE_FINDINGS, tmp)
        tmp.close()
        findings_file = tmp.name
        hosts = SAMPLE_HOSTS
    else:
        hosts = None  # derive from findings

    out = generate_report(
        findings_path=findings_file,
        hosts_data=hosts,
        output_path="reports/network_audit_report.pdf",
        target="10.0.2.0/24",
    )
    print(f"[+] Report saved → {out}")
