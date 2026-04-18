import argparse, os
from rich.console import Console
from rich.panel import Panel

console = Console()

def main():
    parser = argparse.ArgumentParser(description="Network Audit Tool")
    parser.add_argument("--target",   default=None)
    parser.add_argument("--duration", default=None, type=int)
    args = parser.parse_args()

    console.print(Panel(
        "[bold cyan]Network Audit Tool v1.0[/bold cyan]\n"
        "Phase 2: Nmap Scanner",
        border_style="cyan"
    ))

    from scanner.nmap_scanner import run_nmap_scan
    hosts, summary = run_nmap_scan(target=args.target)

    console.print(f"\n[bold green]Scan complete![/bold green]")
    console.print(f"  Hosts found : {summary.get('total_hosts', 0)}")
    console.print(f"  Open ports  : {summary.get('total_ports', 0)}")
    console.print(f"  Risky ports : {summary.get('risky_ports', 0)}")

if __name__ == "__main__":
    main()
