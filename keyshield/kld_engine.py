"""
kld_engine.py  –  Detection engine for KeyShield
Author: (your name here)

Performs:
  1. Userspace detection  – finds processes with an open handle on /dev/input/event*
  2. Kernel-module detection – compares live lsmod output against a trusted whitelist
                               and probes suspicious modules with a SystemTap script
"""

import os
import sys
import signal
import subprocess


# ──────────────────────────────────────────────────────────
# Platform / privilege guards
# ──────────────────────────────────────────────────────────

def assert_linux():
    if sys.platform != "linux":
        raise RuntimeError("KeyShield only runs on Linux.")

def assert_root():
    if os.getuid() != 0:
        raise PermissionError("Root privileges required. Re-run with sudo.")

def assert_dependencies():
    missing = [pkg for pkg in ("fuser", "which")
               if subprocess.call(["which", pkg],
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL) != 0]
    if missing:
        raise EnvironmentError(f"Missing system packages: {', '.join(missing)}")


# ──────────────────────────────────────────────────────────
# Device / process helpers
# ──────────────────────────────────────────────────────────

def _resolve_path(path: str) -> str:
    return os.path.realpath(path) if os.path.islink(path) else path


def find_keyboard_devices(identifiers: list) -> list:
    """
    Walk /dev/input/by-path and return real paths of entries whose
    filename contains any of the given identifier strings (e.g. 'kbd').
    """
    devices = []
    base = "/dev/input/by-path"
    if not os.path.isdir(base):
        return devices
    for entry in os.listdir(base):
        if any(ident in entry for ident in identifiers):
            devices.append(_resolve_path(os.path.join(base, entry)))
    return devices


def pids_for_device(device_path: str) -> list:
    """Return list of PID strings that currently have device_path open."""
    try:
        raw = subprocess.check_output(
            ["fuser", device_path],
            stderr=subprocess.DEVNULL
        ).decode().split()
        return raw
    except subprocess.CalledProcessError:
        return []


def process_name(pid: str) -> str:
    try:
        with open(f"/proc/{pid}/comm") as fh:
            return fh.read().strip()
    except IOError:
        return f"<pid:{pid}>"


def kill_pid(pid: str) -> bool:
    try:
        os.kill(int(pid), signal.SIGKILL)
        return True
    except (ProcessLookupError, ValueError):
        return False


def kill_by_name(name: str, name_pid_map: dict) -> list:
    """Kill all PIDs associated with a process name. Returns killed PIDs."""
    killed = []
    for pid in name_pid_map.get(name, []):
        if kill_pid(pid):
            killed.append(pid)
    return killed


# ──────────────────────────────────────────────────────────
# Main userspace scan
# ──────────────────────────────────────────────────────────

def scan_userspace(kbd_identifiers: list) -> tuple:
    """
    Scan /dev/input/* for processes accessing keyboard devices.

    Returns:
        devices       – list of device paths scanned
        name_pid_map  – {process_name: [pid, ...]}
        all_names     – sorted list of unique process names
    """
    devices = find_keyboard_devices(kbd_identifiers)

    all_pids = []
    for dev in devices:
        all_pids.extend(pids_for_device(dev))
    all_pids = sorted(set(all_pids))

    name_pid_map = {}
    for pid in all_pids:
        name = process_name(pid)
        name_pid_map.setdefault(name, []).append(pid)

    return devices, name_pid_map, sorted(name_pid_map.keys())


def get_suspicious(all_names: list, whitelist: list, blacklist: list,
                   auto_kill_active: bool) -> list:
    """
    Filter process names down to those that are suspicious
    (not whitelisted, and not already auto-killed via blacklist).
    """
    suspicious = []
    for name in all_names:
        if name in whitelist:
            continue
        if name in blacklist and auto_kill_active:
            continue          # already handled by auto-kill
        suspicious.append(name)
    return suspicious


# ──────────────────────────────────────────────────────────
# Kernel-module detection
# ──────────────────────────────────────────────────────────

def load_module_whitelist(path: str) -> list:
    try:
        with open(path) as fh:
            return [line.split()[0] for line in fh if line.strip()]
    except IOError:
        return []


def live_modules() -> list:
    try:
        raw = subprocess.check_output(["lsmod"], text=True)
        return [line.split()[0] for line in raw.strip().splitlines() if line.split()]
    except subprocess.CalledProcessError:
        return []


def suspect_modules(live: list, trusted: list) -> list:
    return list(set(live) - set(trusted))


def _find_ko_path(module_name: str) -> str:
    """Locate the .ko file for a module by walking /."""
    filename = module_name + ".ko"
    for root, _, files in os.walk("/"):
        if filename in files:
            return os.path.join(root, filename)
    return ""


def probe_module_with_stap(module_path: str, stap_script: str) -> bool:
    """
    Insert a module, run a SystemTap probe for 10 s, remove the module.
    Returns True if the module registered a keyboard notifier.
    """
    try:
        subprocess.Popen(["sudo", "insmod", module_path])
        proc = subprocess.Popen(
            ["stap", stap_script, "-T", "10"],
            stdout=subprocess.PIPE, text=True
        )
        subprocess.Popen(["sudo", "rmmod", module_path])
        output, _ = proc.communicate()
        subprocess.Popen(["sudo", "insmod", module_path])
        return "[-]" in output
    except Exception:
        return False


def scan_kernel_modules(whitelist_path: str, stap_script: str) -> list:
    """
    Full kernel-module scan.
    Returns list of module paths confirmed to be keyboard loggers.
    """
    trusted   = load_module_whitelist(whitelist_path)
    live      = live_modules()
    suspects  = suspect_modules(live, trusted)

    confirmed = []
    for mod_name in suspects:
        mod_path = _find_ko_path(mod_name)
        if not mod_path:
            continue
        if probe_module_with_stap(mod_path, stap_script):
            confirmed.append(mod_path)

    return confirmed


def unload_module(module_path: str) -> bool:
    result = subprocess.run(
        ["sudo", "rmmod", module_path],
        capture_output=True, text=True
    )
    return result.returncode == 0
