#!/usr/bin/env python3
"""
keyshield.py  –  KeyShield: Keylogger Detection Tool
Author: (your name here)

An original, from-scratch Linux keylogger detector with a professional
terminal UI.  Detects both userspace processes and kernel modules that
hook into keyboard input events.

Usage:
    sudo python3 keyshield.py [OPTIONS]

Options:
    -h, --help       Show help
    -v, --verbose    Verbose output
    -a, --auto-kill  Auto-kill blacklisted processes
    -s, --safe       Confirm before killing
    -w, --whitelist  Prompt to add to whitelist
    -b, --blacklist  Auto-blacklist killed processes
    -d, --debug      Debug output
    -k, --kernel     Kernel-module detection (needs SystemTap)

Requirements:
    pip install rich
    System: fuser, which, lsmod
    Optional: stap (SystemTap) for kernel detection
"""

import sys
import os

# ── Optional: locate stap script next to this file ──
_HERE       = os.path.dirname(os.path.abspath(__file__))
_STAP_FILE  = os.path.join(_HERE, "funcall_trace.stp")
_WL_FILE    = os.path.join(_HERE, "whitelist.txt")

# ── CLI flag parsing ──────────────────────────────────────────────────────────

def _parse_args(argv):
    flags = dict(
        verbose=False, auto_kill=False, safe=False,
        whitelist=False, blacklist=False, debug=False,
        kernel=False, help=False,
    )
    mapping = {
        "-h": "help",   "--help":       "help",
        "-v": "verbose","--verbose":    "verbose",
        "-a": "auto_kill","--auto-kill":"auto_kill",
        "-s": "safe",   "--safe":       "safe",
        "-w": "whitelist","--whitelist":"whitelist",
        "-b": "blacklist","--blacklist":"blacklist",
        "-d": "debug",  "--debug":      "debug",
        "-k": "kernel", "--kernel":     "kernel",
    }
    for arg in argv[1:]:
        if arg in mapping:
            flags[mapping[arg]] = True
    return flags


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    # Late imports so --help works even without rich
    from kld_ui     import (console, print_banner, print_help,
                             show_init_phase, show_scan_phase,
                             show_results, prompt_kill, confirm_kill,
                             prompt_whitelist, show_kernel_results, show_done,
                             ok, warn, err, info, dim, progress_bar)
    from kld_engine import (assert_linux, assert_root, assert_dependencies,
                             scan_userspace, get_suspicious,
                             kill_by_name, kill_pid,
                             scan_kernel_modules, unload_module)
    from kld_config import load_config, save_config

    flags = _parse_args(sys.argv)

    print_banner()

    if flags["help"]:
        print_help()
        sys.exit(0)

    # ── 1. Platform / privilege checks ────────────────────────────────────────
    root_ok = deps_ok = True
    try:
        assert_linux()
    except RuntimeError as exc:
        err(str(exc)); sys.exit(1)

    try:
        assert_root()
    except PermissionError as exc:
        err(str(exc)); root_ok = False

    try:
        assert_dependencies()
    except EnvironmentError as exc:
        err(str(exc)); deps_ok = False

    cfg = load_config()
    whitelist = cfg["whitelist"]
    blacklist = cfg["blacklist"]
    kbd_ids   = cfg["kbd_identifiers"]

    show_init_phase(root_ok, deps_ok, whitelist, blacklist)

    if not root_ok or not deps_ok:
        sys.exit(1)

    # ── 2. Userspace scan ─────────────────────────────────────────────────────
    devices, name_pid_map, all_names = scan_userspace(kbd_ids)
    show_scan_phase(devices, name_pid_map, verbose=flags["verbose"])

    if flags["debug"]:
        dim(f"Devices:  {devices}")
        dim(f"Processes: {all_names}")

    # ── 3. Auto-kill blacklisted ───────────────────────────────────────────────
    if flags["auto_kill"]:
        for name in all_names:
            if name in blacklist:
                if flags["safe"]:
                    if confirm_kill(name):
                        killed = kill_by_name(name, name_pid_map)
                        warn(f"Auto-killed [red]{name}[/red]  PIDs {killed}")
                else:
                    killed = kill_by_name(name, name_pid_map)
                    warn(f"Auto-killed [red]{name}[/red]  PIDs {killed}")

    # ── 4. Filter suspicious ──────────────────────────────────────────────────
    suspicious = get_suspicious(all_names, whitelist, blacklist,
                                auto_kill_active=flags["auto_kill"])

    # ── 5. Show results ───────────────────────────────────────────────────────
    show_results(suspicious, name_pid_map)

    if not suspicious and not flags["kernel"]:
        show_done()
        sys.exit(0)

    # ── 6. Kill prompt ────────────────────────────────────────────────────────
    to_kill = []
    if suspicious:
        to_kill = prompt_kill(suspicious)

        if not to_kill:
            info("No processes selected for termination.")
        else:
            for name in to_kill:
                if name not in name_pid_map:
                    warn(f"Process [yellow]{name}[/yellow] not found in scan results – skipping.")
                    continue
                if flags["safe"]:
                    for pid in name_pid_map[name]:
                        if confirm_kill(name):
                            if kill_pid(pid):
                                ok(f"Killed [red]{name}[/red]  PID {pid}")
                            else:
                                err(f"Failed to kill {name}  PID {pid}")
                else:
                    killed = kill_by_name(name, name_pid_map)
                    if killed:
                        ok(f"Killed [red]{name}[/red]  PIDs {killed}")
                    else:
                        err(f"Failed to kill {name}")

        # ── 7. Whitelist / blacklist updates ──────────────────────────────────
        if flags["whitelist"]:
            additions = prompt_whitelist()
            if additions:
                whitelist.extend(additions)
                ok(f"Whitelisted: [green]{', '.join(additions)}[/green]")

        if flags["blacklist"] and to_kill:
            new_bl = [n for n in set(to_kill) if n not in blacklist]
            blacklist.extend(new_bl)
            ok(f"Blacklisted: [red]{', '.join(new_bl)}[/red]")

    # ── 8. Persist config ─────────────────────────────────────────────────────
    cfg["whitelist"]      = list(set(whitelist))
    cfg["blacklist"]      = list(set(blacklist))
    cfg["kbd_identifiers"] = list(set(kbd_ids))
    save_config(cfg)

    if flags["debug"]:
        dim(f"Config saved to keyshield_config.json")

    # ── 9. Kernel detection ───────────────────────────────────────────────────
    if flags["kernel"]:
        if not os.path.isfile(_STAP_FILE):
            err(f"SystemTap script not found at {_STAP_FILE}")
        elif not os.path.isfile(_WL_FILE):
            err(f"Module whitelist not found at {_WL_FILE}  –  "
                "run:  lsmod > whitelist.txt")
        else:
            progress_bar("Analysing kernel modules …", steps=35, delay=0.06)
            confirmed = scan_kernel_modules(_WL_FILE, _STAP_FILE)
            indices   = show_kernel_results(confirmed) or []
            for idx in indices:
                if 0 <= idx < len(confirmed):
                    if unload_module(confirmed[idx]):
                        ok(f"Unloaded module: [red]{confirmed[idx]}[/red]")
                    else:
                        err(f"Failed to unload: {confirmed[idx]}")

    # ── 10. Done ──────────────────────────────────────────────────────────────
    show_done()


if __name__ == "__main__":
    main()
