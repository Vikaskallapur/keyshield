"""
kld_ui.py  –  Terminal UI for KeyShield
Author: (your name here)

Requires:  pip install rich
"""

import random
import time

try:
    from rich.console import Console
    from rich.panel   import Panel
    from rich.table   import Table
    from rich.text    import Text
    from rich.rule    import Rule
    from rich.align   import Align
    from rich.progress import (Progress, SpinnerColumn,
                               BarColumn, TextColumn, TimeElapsedColumn)
    from rich         import box
except ImportError:
    raise SystemExit("[!] Install rich first:  pip install rich")

console = Console()

# ─────────────────────────── palette ────────────────────────────
C_OK      = "bold bright_green"
C_WARN    = "bold yellow"
C_ERR     = "bold red"
C_INFO    = "bold cyan"
C_DIM     = "dim white"
C_BANNER  = "bold green"
C_ACCENT  = "bright_cyan"

# ─────────────────────────── banner ─────────────────────────────
_BANNER = r"""
 ██╗  ██╗███████╗██╗   ██╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗ 
 ██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
 █████╔╝ █████╗   ╚████╔╝ ███████╗███████║██║█████╗  ██║     ██║  ██║
 ██╔═██╗ ██╔══╝    ╚██╔╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
 ██║  ██╗███████╗   ██║   ███████║██║  ██║██║███████╗███████╗██████╔╝
 ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ 
"""

_TIPS = [
    "Run with [bold]-k[/bold] to enable kernel-module detection",
    "Use [bold]-s[/bold] (safe mode) to confirm each kill interactively",
    "Add trusted processes with [bold]-w[/bold] to avoid false positives",
    "Blacklist repeat offenders automatically with [bold]-b[/bold]",
    "Always snapshot lsmod to whitelist.txt before testing kernel mods",
]

_THREAT = {
    "python3":    (5, "CRITICAL"),
    "perl":       (5, "CRITICAL"),
    "ruby":       (4, "HIGH"),
    "bash":       (3, "MEDIUM"),
    "sh":         (3, "MEDIUM"),
    "Xorg":       (1, "LOW"),
    "systemd-logind": (0, "SYSTEM"),
}


def _threat_row(name: str):
    level_val, label = _THREAT.get(name, (3, "UNKNOWN"))
    bar   = "█" * level_val + "░" * (5 - level_val)
    color = {
        "CRITICAL": "bold red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "dim yellow",
        "SYSTEM":   "dim cyan",
        "UNKNOWN":  "bold white",
    }[label]
    return f"[{color}]{bar}  {label}[/{color}]"


# ─────────────────────────── helpers ────────────────────────────

def _rule(title: str = ""):
    console.print()
    console.print(Rule(f"[bold white]{title}[/bold white]", style="dim green"))
    console.print()

def ok(msg):   console.print(f"  [{C_OK}][[+]][/{C_OK}] {msg}")
def warn(msg): console.print(f"  [{C_WARN}][[-]][/{C_WARN}] {msg}")
def err(msg):  console.print(f"  [{C_ERR}][[!]][/{C_ERR}] {msg}")
def info(msg): console.print(f"  [{C_INFO}][[*]][/{C_INFO}] {msg}")
def dim(msg):  console.print(f"  [{C_DIM}]  [~]  {msg}[/{C_DIM}]")


def progress_bar(label: str, steps: int = 20, delay: float = 0.04):
    with Progress(
        SpinnerColumn(spinner_name="dots2", style=C_OK),
        TextColumn(f"[{C_INFO}]{label}[/{C_INFO}]"),
        BarColumn(bar_width=36, style="green", complete_style="bright_green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as prog:
        task = prog.add_task("", total=steps)
        for _ in range(steps):
            time.sleep(delay)
            prog.advance(task)


# ─────────────────────────── public API ─────────────────────────

def print_banner():
    console.print(_BANNER, style=C_BANNER)
    console.print(Align.center(
        Text("[ Keylogger Detection Tool  v2.0 ]", style=f"bold {C_ACCENT}")))
    console.print(Align.center(
        Text("Linux  |  Userspace + Kernel Detection  |  Original Work", style=C_DIM)))
    console.print()
    console.print(Panel(
        f"[{C_WARN}]Tip:[/{C_WARN}]  {random.choice(_TIPS)}",
        border_style="dim yellow", padding=(0, 2)
    ))
    console.print()


def print_help():
    _rule("USAGE")
    console.print("  [bold white]sudo python3 keyshield.py[/bold white] [dim][OPTIONS][/dim]\n")
    rows = [
        ("-h, --help",            "Show this help message"),
        ("-v, --verbose",         "Verbose output during each phase"),
        ("-a, --auto-kill",       "Automatically terminate blacklisted processes"),
        ("-s, --safe",            "Confirm each kill before executing"),
        ("-w, --whitelist",       "Prompt to add processes to the whitelist"),
        ("-b, --blacklist",       "Add killed processes to the auto-kill blacklist"),
        ("-d, --debug",           "Print internal debug information"),
        ("-k, --kernel",          "Enable kernel-module detection (requires SystemTap)"),
    ]
    t = Table(box=box.SIMPLE, show_header=False,
              border_style="dim green", padding=(0, 2))
    t.add_column("Flag",  style="bold cyan",  min_width=22)
    t.add_column("Desc",  style="white")
    for flag, desc in rows:
        t.add_row(flag, desc)
    console.print(t)
    console.print()


def show_init_phase(root_ok: bool, deps_ok: bool, whitelist: list, blacklist: list):
    _rule("INITIALIZATION")
    progress_bar("Checking platform & privileges …", steps=12, delay=0.03)
    if root_ok:
        ok("Running as root")
    else:
        err("Root check failed")

    progress_bar("Verifying system dependencies …",  steps=10, delay=0.03)
    if deps_ok:
        ok("Dependencies satisfied: [green]fuser[/green], [green]which[/green]")
    else:
        err("Missing dependencies")

    ok(f"Config loaded — whitelist: [green]{len(whitelist)}[/green]"
       f"  blacklist: [yellow]{len(blacklist)}[/yellow]")


def show_scan_phase(devices: list, name_pid_map: dict, verbose: bool = False):
    _rule("SCANNING INPUT DEVICES")
    progress_bar("Enumerating /dev/input/event* devices …", steps=22, delay=0.04)
    if devices:
        info(f"Keyboard devices found: [yellow]{', '.join(devices)}[/yellow]")
    else:
        warn("No keyboard devices found under /dev/input/by-path")

    progress_bar("Mapping processes to input handles …",   steps=28, delay=0.04)
    if verbose:
        for name, pids in name_pid_map.items():
            dim(f"{name}  →  PIDs {pids}")


def show_results(suspicious: list, name_pid_map: dict):
    _rule("SCAN RESULTS")

    if not suspicious:
        ok("[bold green]System appears clean — no suspicious processes detected.[/bold green]")
        return

    warn(f"[bold red]{len(suspicious)}[/bold red] "
         "suspicious process(es) detected accessing keyboard hardware!")
    console.print()

    t = Table(
        title="[bold red]⚠   SUSPICIOUS PROCESSES   ⚠[/bold red]",
        box=box.DOUBLE_EDGE,
        border_style="red",
        header_style="bold white on dark_red",
        show_lines=True,
        padding=(0, 1),
    )
    t.add_column("#",            style="dim",        width=4,  justify="right")
    t.add_column("Process",      style="bold red",   min_width=18)
    t.add_column("PID(s)",       style="yellow",     min_width=14)
    t.add_column("Status",       style="bold",       min_width=10)
    t.add_column("Threat Level", min_width=18)

    for i, name in enumerate(suspicious, 1):
        pids = ", ".join(str(p) for p in name_pid_map.get(name, []))
        t.add_row(str(i), name, pids, "[yellow]ACTIVE[/yellow]", _threat_row(name))

    console.print(Align.center(t))
    console.print()


def prompt_kill(suspicious: list) -> list:
    _rule("PROCESS TERMINATION")
    console.print(Panel(
        "[bold white]Enter process names to terminate, separated by spaces.\n"
        "[dim]Press ENTER with no input to skip termination.[/dim]",
        border_style="red", padding=(0, 2),
        title="[bold red]TERMINATE[/bold red]"
    ))
    avail = "  [dim]Targets:[/dim] [yellow]" + "   ".join(suspicious) + "[/yellow]"
    console.print(avail)
    console.print()
    raw = console.input(
        "  [bold red]keyshield[/bold red] [white]>[/white] "
        "[bold green]kill[/bold green] [cyan]›[/cyan] "
    )
    return raw.strip().split() if raw.strip() else []


def confirm_kill(name: str) -> bool:
    answer = console.input(
        f"  [{C_WARN}][[!]][/{C_WARN}] Kill [bold yellow]{name}[/bold yellow]? "
        f"[dim](y/N)[/dim] "
    ).strip().lower()
    return answer == "y"


def prompt_whitelist() -> list:
    _rule("WHITELIST UPDATE")
    info("Enter process names to add to the whitelist (space-separated):")
    raw = console.input(
        "  [bold cyan]keyshield[/bold cyan] [white]>[/white] "
        "[bold green]whitelist[/bold green] [cyan]›[/cyan] "
    )
    return raw.strip().split() if raw.strip() else []


def show_kernel_results(confirmed: list):
    _rule("KERNEL MODULE ANALYSIS")
    if not confirmed:
        ok("No malicious kernel modules detected.")
        return

    warn(f"[bold red]{len(confirmed)}[/bold red] kernel keylogger module(s) identified!")
    console.print()

    t = Table(
        title="[bold red]⚠   KERNEL KEYLOGGER MODULES   ⚠[/bold red]",
        box=box.HEAVY_EDGE, border_style="red",
        header_style="bold white on dark_red", padding=(0, 1),
    )
    t.add_column("#",       style="dim",      width=4, justify="right")
    t.add_column("Module",  style="bold red", min_width=40)
    t.add_column("Action",  style="yellow")

    for i, path in enumerate(confirmed, 1):
        t.add_row(str(i), path, "[red]UNLOAD RECOMMENDED[/red]")

    console.print(Align.center(t))
    console.print()

    raw = console.input(
        "  [bold red]keyshield[/bold red] [white]>[/white] "
        "[bold green]rmmod[/bold green] [cyan]›[/cyan] "
        "Enter indices to unload (space-separated, ENTER to skip): "
    )
    return [int(x) - 1 for x in raw.strip().split() if x.isdigit()]


def show_done():
    console.print()
    console.print(Rule(style="dim green"))
    console.print()
    console.print(Align.center(Panel(
        "[bold green]✔  Scan complete.[/bold green]\n"
        "[dim]Stay vigilant. Stay secure.[/dim]",
        border_style="green", padding=(1, 6),
    )))
    console.print()
