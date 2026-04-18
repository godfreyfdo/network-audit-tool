# =============================================================================
# main.py — Pipeline Orchestrator
# Phases will be added here as each one is built.
# =============================================================================

import argparse
import sys
import os
from rich.console import Console
from rich.panel import Panel

console = Console()

def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Audit Tool — Nmap + Wireshark anomaly detector"
    )
    parser.add_argument("--target",   default=None, help="Target network e.g. 192.168.1.0/24")
    parser.add_argument("--duration", default=None, type=int, help="Capture duration in seconds")
    parser.add_argument("--output",   default="reports/", help="Output directory for PDF")
    return parser.parse_args()


def main():
    args = parse_args()

    console.print(Panel(
        "[bold cyan]Network Audit Tool v1.0[/bold cyan]\n"
        "Phase 2: Nmap Scanner — Active\n"
        "Phases 3–7: Coming soon",
        border_style="cyan"
    ))

    # ── Phase 2: Nmap Scan ────────────────────────────────────────────────────
    from scanner.nmap_scanner import run_nmap_scan
    hosts, summary = run_nmap_scan(target=args.target)

    console.print(f"\n[bold green]Phase 2 complete.[/bold green]")
    console.print(f"  Hosts found:  {summary.get('total_hosts', 0)}")
    console.print(f"  Open ports:   {summary.get('total_ports', 0)}")
    console.print(f"  Risky ports:  {summary.get('risky_ports', 0)}")
    console.print("\n[dim]Phases 3–7 will be added in subsequent sessions.[/dim]")


if __name__ == "__main__":
    main()
