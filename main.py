import argparse
from rich.console import Console
from rich.panel import Panel

console = Console()

def main():
    parser = argparse.ArgumentParser(description="Network Audit Tool")
    parser.add_argument("--target",    default=None)
    parser.add_argument("--duration",  default=60, type=int)
    parser.add_argument("--interface", default=None)
    args = parser.parse_args()

    console.print(Panel(
        "[bold cyan]Network Audit Tool v1.0[/bold cyan]\n"
        "Phase 2: Nmap Scanner  [green]✓[/green]\n"
        "Phase 3: Traffic Capture  [yellow]running...[/yellow]",
        border_style="cyan"
    ))

    # Phase 2
    from scanner.nmap_scanner import run_nmap_scan
    hosts, summary = run_nmap_scan(target=args.target)
    console.print(f"[green]Phase 2 done.[/green] Hosts: {summary.get('total_hosts',0)} | Risky ports: {summary.get('risky_ports',0)}\n")

    # Phase 3
    from scanner.wireshark_capture import run_capture
    pcap_file = run_capture(interface=args.interface, duration=args.duration)

    if pcap_file:
        console.print(f"[green]Phase 3 done.[/green] pcap saved → {pcap_file}")
    else:
        console.print("[red]Phase 3 failed — check tshark is installed.[/red]")

if __name__ == "__main__":
    main()
