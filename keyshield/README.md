# KeyShield — Keylogger Detection Tool

An original, from-scratch Linux keylogger detector with a professional
Metasploit-style terminal UI.

## Features

- **Userspace detection** — finds any process with an open handle on `/dev/input/event*` (the classic keylogger technique)
- **Kernel-module detection** — compares live `lsmod` output against a trusted whitelist, then probes suspects with a SystemTap script
- **Threat-level table** — colour-coded output with per-process risk ratings
- **Whitelist / blacklist management** — persistent config so known-safe processes are never flagged again
- **Safe mode** — confirms every kill before executing
- **Auto-kill mode** — silently terminates known-bad processes

## Requirements

```bash
pip install rich          # terminal UI
# System tools (usually pre-installed on Kali/Ubuntu):
# fuser, which, lsmod
# Optional for kernel detection:
# stap  (SystemTap)
```

## Setup

```bash
# Clone or copy these files into one directory:
#   keyshield.py   kld_engine.py   kld_ui.py
#   kld_config.py  funcall_trace.stp

# Snapshot your current trusted kernel modules BEFORE testing:
lsmod > whitelist.txt
```

## Usage

```bash
# Basic scan (userspace only)
sudo python3 keyshield.py

# Verbose scan with kernel-module detection
sudo python3 keyshield.py -v -k

# Auto-kill blacklisted + safe confirmation
sudo python3 keyshield.py -a -s

# All options
sudo python3 keyshield.py -h
```

## File Layout

| File                  | Purpose                              |
|-----------------------|--------------------------------------|
| `keyshield.py`        | Entry point & control flow           |
| `kld_engine.py`       | Detection logic (no UI dependency)   |
| `kld_ui.py`           | Rich terminal UI layer               |
| `kld_config.py`       | JSON config load/save                |
| `funcall_trace.stp`   | SystemTap probe for kernel detection |
| `whitelist.txt`       | Trusted module snapshot (you create) |

## Warning

- Must run as **root** (`sudo`)
- Kernel detection requires **SystemTap** (`stap`) to be installed
- Test kernel-module detection in a **VM** first — unloading wrong modules can crash the system
- Run `lsmod > whitelist.txt` on a clean system before enabling `-k`
