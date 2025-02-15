import time
import json
import os

DEVICE_LOG_FILE = "known_devices.json"

# Load known devices
if os.path.exists(DEVICE_LOG_FILE):
    with open(DEVICE_LOG_FILE, "r") as f:
        device_log = json.load(f)
else:
    device_log = {}

def save_device_log():
    """Save the device log to a JSON file."""
    with open(DEVICE_LOG_FILE, "w") as f:
        json.dump(device_log, f)

def update_device_log(mac):
    """Track how many times a device connects and how long it stays."""
    current_time = time.time()
    if mac in device_log:
        device_log[mac]["count"] += 1
        device_log[mac]["last_seen"] = current_time
    else:
        device_log[mac] = {
            "count": 1,
            "first_seen": current_time,
            "last_seen": current_time
        }
    save_device_log()

def get_device_info(mac):
    """Get connection details of a device."""
    if mac in device_log:
        first_seen = device_log[mac]["first_seen"]
        last_seen = device_log[mac]["last_seen"]
        duration = round(last_seen - first_seen, 2)
        return device_log[mac]["count"], duration
    return 0, 0
