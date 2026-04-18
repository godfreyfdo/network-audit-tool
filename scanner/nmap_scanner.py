import nmap, json, os, sys
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import config

console = Console()

class NmapScanner:
    def __init__(self, target=None, arguments=None):
        self.target    = target    or config.TARGET_NETWORK
        self.arguments = arguments or config.NMAP_ARGUMENTS
        self.nm        = None
        self.hosts     = []
        self.scan_time = None

    def scan(self):
        if self.nm is None:
            self.nm = nmap.PortScanner()
        console.print(Panel(
            f"[bold]Target:[/bold]    {self.target}\n"
            f"[bold]Arguments:[/bold] {self.arguments}\n"
            f"[bold]Started:[/bold]   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            title="[cyan]Phase 2 — Nmap Scan[/cyan]", border_style="cyan"
        ))
        console.print("[yellow]  Running scan... 1-3 minutes.[/yellow]")
        try:
            self.nm.scan(hosts=self.target, arguments=self.arguments)
        except nmap.PortScannerError as e:
            console.print(f"[red]  Error: {e}[/red]")
            self.nm.scan(hosts=self.target, arguments="-sV --open -T4")
        self.scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._save_xml()
        self.hosts = self._parse_hosts()
        self._print_table()
        console.print(f"[green]  Done. {len(self.hosts)} host(s) found.[/green]\n")
        return self.hosts

    def parse(self):
        return self._parse_hosts()

    def get_summary(self):
        if not self.hosts:
            return {}
        return {
            "total_hosts": len(self.hosts),
            "total_ports": sum(len(h["open_ports"]) for h in self.hosts),
            "risky_ports": sum(1 for h in self.hosts for p in h["open_ports"] if p["is_risky"]),
            "scan_time":   self.scan_time,
            "target":      self.target,
        }

    def _save_xml(self):
        os.makedirs(os.path.dirname(config.NMAP_OUTPUT_FILE), exist_ok=True)
        with open(config.NMAP_OUTPUT_FILE, "w") as f:
            f.write(self.nm.get_nmap_last_output().decode("utf-8") if isinstance(self.nm.get_nmap_last_output(), bytes) else self.nm.get_nmap_last_output())

    def _parse_hosts(self):
        hosts = []
        for ip in self.nm.all_hosts():
            hd       = self.nm[ip]
            hostnames = hd.hostnames()
            hostname  = hostnames[0]["name"] if hostnames and hostnames[0]["name"] else ""
            os_name, os_acc = "Unknown", 0
            if "osmatch" in hd and hd["osmatch"]:
                os_name = hd["osmatch"][0].get("name", "Unknown")
                os_acc  = int(hd["osmatch"][0].get("accuracy", 0))
            open_ports = []
            for proto in hd.all_protocols():
                for port in sorted(hd[proto].keys()):
                    pi = hd[proto][port]
                    if pi["state"] != "open":
                        continue
                    is_risky  = port in config.RISKY_PORTS
                    open_ports.append({
                        "port": port, "protocol": proto,
                        "service":   pi.get("name", "unknown"),
                        "version":   pi.get("version", ""),
                        "state":     pi["state"],
                        "is_risky":  is_risky,
                        "risk_info": config.RISKY_PORTS.get(port, {}),
                    })
            risky = sum(1 for p in open_ports if p["is_risky"])
            hosts.append({
                "ip": ip, "hostname": hostname,
                "state": hd.state(), "os": os_name, "os_accuracy": os_acc,
                "open_ports": open_ports, "risky_port_count": risky,
                "scanned_at": self.scan_time,
            })
        hosts.sort(key=lambda h: h["risky_port_count"], reverse=True)
        return hosts

    def _print_table(self):
        if not self.hosts:
            console.print("[yellow]  No hosts found.[/yellow]")
            return
        t = Table(title=f"Results — {self.target}", box=box.ROUNDED, border_style="cyan", show_lines=True)
        t.add_column("IP",          style="cyan",   no_wrap=True)
        t.add_column("Hostname",    style="white")
        t.add_column("OS",          style="dim")
        t.add_column("Open Ports",  style="yellow", justify="center")
        t.add_column("Risky",       style="red",    justify="center")
        t.add_column("Risk Level",  justify="center")
        for h in self.hosts:
            rc = h["risky_port_count"]
            rl = "[green]Clean[/green]" if rc==0 else "[yellow]Medium[/yellow]" if rc<=2 else "[red]High[/red]"
            t.add_row(
                h["ip"], h["hostname"] or "[dim]no hostname[/dim]",
                f"{h['os']} ({h['os_accuracy']}%)" if h["os"]!="Unknown" else "[dim]Unknown[/dim]",
                ", ".join(str(p["port"]) for p in h["open_ports"]) or "—",
                str(rc) if rc>0 else "[green]0[/green]", rl,
            )
        console.print(t)

def run_nmap_scan(target=None, arguments=None):
    scanner = NmapScanner(target=target, arguments=arguments)
    hosts   = scanner.scan()
    return hosts, scanner.get_summary()

if __name__ == "__main__":
    hosts, summary = run_nmap_scan()
    console.print_json(json.dumps(summary, indent=2))
