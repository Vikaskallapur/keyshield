"""
kld_config.py  –  Configuration management for KeyShield
Author: (your name here)
"""

import json
import os

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'keyshield_config.json')

DEFAULT_CONFIG = {
    "whitelist": [
        "systemd-logind",
        "systemd",
        "gnome-shell",
        "Xorg",
        "sddm",
        "gdm",
        "lightdm"
    ],
    "blacklist": [],
    "kbd_identifiers": ["kbd", "keyboard"]
}


def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as fh:
                return json.load(fh)
        except (json.JSONDecodeError, IOError):
            pass
    # First run – create default
    save_config(DEFAULT_CONFIG.copy())
    return DEFAULT_CONFIG.copy()


def save_config(cfg: dict) -> bool:
    try:
        with open(CONFIG_FILE, 'w') as fh:
            json.dump(cfg, fh, indent=4)
        return True
    except IOError:
        return False
