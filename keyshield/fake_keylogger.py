import time

device = "/dev/input/event0"

print("[*] Fake keylogger started (demo only)...")

try:
    with open(device, "rb") as f:
        while True:
            data = f.read(24)  # read raw input events
            if data:
                print("[*] Reading input event...")
            time.sleep(0.1)
except PermissionError:
    print("[!] Run with sudo")
except KeyboardInterrupt:
    print("\n[*] Stopped.")
