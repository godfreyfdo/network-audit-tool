# =============================================================================
# scanner/nmap_scanner.py
# Phase 2 — Nmap Scanner Module
#
# Responsibilities:
#   1. Run nmap against the target network with full service/OS detection
#   2. Parse the XML output into clean Python dicts
#   3. Flag any open risky ports against the RISKY_PORTS list in config
#   4. Save raw XML to data/nmap_output.xml
#   5. Return structured host list to the pipeline
# =============================================================================

import nmap
import json
import os
import sys
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

# Local imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import config

console = Console()


# ─────────────────────────────────────────────────────────────────────────────
# Core scanner class
# ─────────────────────────────────────────────────────────────────────────────

class NmapScanner:
    """
    Wraps python-nmap to run scans and parse results into a
    structured format consumed by the rest of the pipeline.
    """

    def __init__(self, target: str = None, arguments: str = None):
        self.target    = target    or config.TARGET_NETWORK
        self.arguments = arguments or config.NMAP_ARGUMENTS
        self.nm        = None  # lazy-init in scan()
        self.hosts     = []          # populated after scan()
        self.scan_time = None

    # ── Public API ────────────────────────────────────────────────────────────

    def scan(self) -> list[dict]:
        """
        Run the nmap scan and return a list of host dicts.
        Also saves raw XML to config.NMAP_OUTPUT_FILE.
        """
        if self.nm is None:
            self.nm = nmap.PortScanner()

        console.print(Panel(
            f"[bold]Target:[/bold]    {self.target}\n"
            f"[bold]Arguments:[/bold] {self.arguments}\n"
            f"[bold]Started:[/bold]   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            title="[cyan]Phase 2 — Nmap Scan[/cyan]",
            border_style="cyan"
        ))

        console.print("[yellow]  Running scan... this may take 1-3 minutes.[/yellow]")

        try:
            self.nm.scan(hosts=self.target, arguments=self.arguments)
        except nmap.PortScannerError as e:
            console.print(f"[red]  Nmap error: {e}[/red]")
            console.print("[red]  Tip: Run with sudo for OS detection (-O flag)[/red]")
            # Retry without OS detection
            console.print("[yellow]  Retrying without OS detection...[/yellow]")
            fallback_args = self.arguments.replace("-O", "").replace("--open", "").strip()
            fallback_args += " --open"
            self.nm.scan(hosts=self.target, arguments=fallback_args)

        self.scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Save raw XML
        self._save_xml()

        # Parse into structured dicts
        self.hosts = self._parse_hosts()

        # Pretty-print results table
        self._print_table()

        console.print(f"[green]  Scan complete. {len(self.hosts)} host(s) found.[/green]\n")
        return self.hosts

    def get_summary(self) -> dict:
        """Return a summary dict for use in the report executive summary."""
        if not self.hosts:
            return {}

        total_hosts = len(self.hosts)
        total_ports = sum(len(h["open_ports"]) for h in self.hosts)
        risky_count = sum(
            1 for h in self.hosts
            for p in h["open_ports"]
            if p["port"] in config.RISKY_PORTS
        )

        return {
            "total_hosts":   total_hosts,
            "total_ports":   total_ports,
            "risky_ports":   risky_count,
            "scan_time":     self.scan_time,
            "target":        self.target,
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    def _save_xml(self):
        """Save raw nmap XML output to data/nmap_output.xml."""
        os.makedirs(os.path.dirname(config.NMAP_OUTPUT_FILE), exist_ok=True)
        with open(config.NMAP_OUTPUT_FILE, "w") as f:
            f.write(self.nm.get_nmap_last_output())
        console.print(f"[dim]  Raw XML saved → {config.NMAP_OUTPUT_FILE}[/dim]")

    def _parse_hosts(self) -> list[dict]:
        """
        Convert nmap's internal data structure into a clean list of dicts.

        Returns:
            [
              {
                "ip":         "192.168.1.1",
                "hostname":   "router.local",
                "state":      "up",
                "os":         "Linux 3.x",
                "os_accuracy": 95,
                "open_ports": [
                  {
                    "port":     80,
                    "protocol": "tcp",
                    "service":  "http",
                    "version":  "Apache httpd 2.4.41",
                    "state":    "open",
                    "is_risky": True,
                    "risk_info": {"name": "HTTP", "risk": "Unencrypted..."}
                  }
                ],
                "risky_port_count": 1,
                "scanned_at": "2025-04-12 10:30:00"
              }
            ]
        """
        hosts = []

        for ip in self.nm.all_hosts():
            host_data = self.nm[ip]

            # ── Hostname ──────────────────────────────────────────────────────
            hostnames = host_data.hostnames()
            hostname  = hostnames[0]["name"] if hostnames and hostnames[0]["name"] else ""

            # ── OS detection ──────────────────────────────────────────────────
            os_name     = "Unknown"
            os_accuracy = 0
            if "osmatch" in host_data and host_data["osmatch"]:
                best_os     = host_data["osmatch"][0]
                os_name     = best_os.get("name", "Unknown")
                os_accuracy = int(best_os.get("accuracy", 0))

            # ── Open ports ────────────────────────────────────────────────────
            open_ports = []
            for proto in host_data.all_protocols():
                ports = sorted(host_data[proto].keys())
                for port in ports:
                    port_info = host_data[proto][port]
                    if port_info["state"] != "open":
                        continue

                    is_risky  = port in config.RISKY_PORTS
                    risk_info = config.RISKY_PORTS.get(port, {})

                    open_ports.append({
                        "port":      port,
                        "protocol":  proto,
                        "service":   port_info.get("name",    "unknown"),
                        "version":   port_info.get("version", ""),
                        "state":     port_info["state"],
                        "is_risky":  is_risky,
                        "risk_info": risk_info,
                    })

            risky_count = sum(1 for p in open_ports if p["is_risky"])

            hosts.append({
                "ip":               ip,
                "hostname":         hostname,
                "state":            host_data.state(),
                "os":               os_name,
                "os_accuracy":      os_accuracy,
                "open_ports":       open_ports,
                "risky_port_count": risky_count,
                "scanned_at":       self.scan_time,
            })

        # Sort: most risky ports first
        hosts.sort(key=lambda h: h["risky_port_count"], reverse=True)
        return hosts


    def parse(self) -> list[dict]:
        """Public alias for _parse_hosts() — used by unit tests."""
        return self._parse_hosts()

    def _print_table(self):
        """Print a rich table of scan results to the terminal."""
        if not self.hosts:
            console.print("[yellow]  No live hosts found.[/yellow]")
            return

        table = Table(
            title=f"Scan Results — {self.target}",
            box=box.ROUNDED,
            border_style="cyan",
            show_lines=True,
        )

        table.add_column("IP Address",   style="cyan",   no_wrap=True)
        table.add_column("Hostname",     style="white")
        table.add_column("OS",           style="dim")
        table.add_column("Open Ports",   style="yellow", justify="center")
        table.add_column("Risky Ports",  style="red",    justify="center")
        table.add_column("Risk Level",   justify="center")

        for host in self.hosts:
            # Determine overall risk label for this host
            rc = host["risky_port_count"]
            if rc == 0:
                risk_label = "[green]Clean[/green]"
            elif rc <= 2:
                risk_label = "[yellow]Medium[/yellow]"
            else:
                risk_label = "[red]High[/red]"

            # List of open port numbers as a string
            port_str = ", ".join(
                str(p["port"]) for p in host["open_ports"]
            ) or "—"

            table.add_row(
                host["ip"],
                host["hostname"] or "[dim]no hostname[/dim]",
                f"{host['os']} ({host['os_accuracy']}%)" if host["os"] != "Unknown" else "[dim]Unknown[/dim]",
                port_str,
                str(rc) if rc > 0 else "[green]0[/green]",
                risk_label,
            )

        console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
# Convenience function — used by main.py
# ─────────────────────────────────────────────────────────────────────────────

def run_nmap_scan(target: str = None, arguments: str = None) -> tuple[list[dict], dict]:
    """
    Run the full nmap scan pipeline.

    Args:
        target:    Network range e.g. "192.168.1.0/24"
        arguments: Nmap flags e.g. "-sV -sC -O --open -T4"

    Returns:
        (hosts list, summary dict)
    """
    scanner = NmapScanner(target=target, arguments=arguments)
    hosts   = scanner.scan()
    summary = scanner.get_summary()
    return hosts, summary


# ─────────────────────────────────────────────────────────────────────────────
# Standalone test — run this file directly to test Phase 2
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    console.print("\n[bold cyan]━━ Phase 2 Standalone Test ━━[/bold cyan]\n")

    hosts, summary = run_nmap_scan()

    # Pretty-print the parsed JSON for inspection
    console.print("\n[bold]Parsed host data (findings.json preview):[/bold]")
    console.print_json(json.dumps(hosts, indent=2))

    console.print("\n[bold]Scan summary:[/bold]")
    console.print_json(json.dumps(summary, indent=2))

    # Save hosts to data/findings.json as a checkpoint
    os.makedirs("data", exist_ok=True)
    with open("data/nmap_hosts.json", "w") as f:
        json.dump({"hosts": hosts, "summary": summary}, f, indent=2)
    console.print(f"\n[green]Hosts saved to data/nmap_hosts.json[/green]")
