import subprocess, os, sys
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import config

console = Console()

class WiresharkCapture:
    def __init__(self, interface=None, duration=None, output_file=None):
        self.interface   = interface   or self._detect_interface()
        self.duration    = duration    or config.CAPTURE_DURATION
        self.output_file = output_file or config.PCAP_OUTPUT_FILE
        self.captured    = False

    def capture(self) -> str:
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)
        console.print(Panel(
            f"[bold]Interface:[/bold] {self.interface}\n"
            f"[bold]Duration:[/bold]  {self.duration} seconds\n"
            f"[bold]Output:[/bold]    {self.output_file}\n"
            f"[bold]Started:[/bold]   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            title="[cyan]Phase 3 — Traffic Capture[/cyan]",
            border_style="cyan"
        ))
        cmd = ["tshark", "-i", self.interface, "-a", f"duration:{self.duration}", "-w", self.output_file, "-q"]
        console.print(f"[yellow]  Capturing {self.duration}s of traffic on {self.interface}...[/yellow]")
        try:
            with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(), transient=True) as p:
                task = p.add_task("  Capturing packets...", total=None)
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                proc.wait()
                p.update(task, description="  Done.")
            if not os.path.exists(self.output_file):
                console.print("[red]  Capture failed — .pcap not created.[/red]")
                console.print("[dim]  Install tshark: sudo apt install tshark -y[/dim]")
                return None
            size = os.path.getsize(self.output_file)
            console.print(f"[green]  Saved → {self.output_file} ({size} bytes)[/green]\n")
            self.captured = True
            return self.output_file
        except FileNotFoundError:
            console.print("[red]  tshark not found. Run: sudo apt install tshark -y[/red]")
            return None
        except Exception as e:
            console.print(f"[red]  Error: {e}[/red]")
            return None

    def _detect_interface(self) -> str:
        try:
            result = subprocess.run(["ip", "route", "get", "8.8.8.8"], capture_output=True, text=True)
            parts = result.stdout.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
        except Exception:
            pass
        return "eth0"


def run_capture(interface=None, duration=None) -> str:
    cap = WiresharkCapture(interface=interface, duration=duration)
    return cap.capture()


if __name__ == "__main__":
    pcap = run_capture(duration=30)
    if pcap:
        console.print(f"[green]Success: {pcap}[/green]")
