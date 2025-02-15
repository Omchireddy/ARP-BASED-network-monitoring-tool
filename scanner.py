import time
import json
import platform
import subprocess
import socket
import re
from email_alert import send_alert
from config import SCAN_INTERVAL

DEVICE_LOG_FILE = "known_devices.json"
DETECTED_DEVICES_FILE = "detected_devices.json"

def load_json(file_path):
    """Load JSON data from a file."""
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_json(data, file_path):
    """Save JSON data to a file."""
    with open(file_path, "w") as f:
        json.dump(data, f)

def get_monitoring_device_ip():
    """Get the IP address of the monitoring device."""
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception as e:
        print(f"⚠️ Error fetching monitoring device IP: {e}")
        return None

def get_router_ip():
    """Get the router's IP address (default gateway)."""
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("ipconfig", shell=True, text=True)
            for line in output.split("\n"):
                if "Default Gateway" in line:
                    return line.split(":")[-1].strip()
        elif platform.system() == "Linux":
            output = subprocess.check_output("ip route", shell=True, text=True)
            return output.split()[2] if "default via" in output else None
    except Exception as e:
        print(f"⚠️ Error fetching router IP: {e}")
        return None

def get_connected_devices():
    """Retrieve all connected devices using ARP scan."""
    devices = {}

    try:
        if platform.system() == "Windows":
            print("🔍 Running ARP scan to detect devices...\n")
            arp_output = subprocess.check_output("arp -a", shell=True, text=True)
            ip_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9:-]+)")

            for line in arp_output.split("\n"):
                match = ip_pattern.search(line)
                if match:
                    ip, mac = match.groups()
                    devices[ip] = {"ip": ip, "mac": mac, "status": "Active"}

    except Exception as e:
        print(f"⚠️ Error scanning devices: {e}")

    return list(devices.values())

def monitor_network():
    """Continuously monitor network every 10 seconds and track connection time and attempts."""
    print("\n🚀 Monitoring started... Press Ctrl+C to stop.\n")

    detected_devices = load_json(DETECTED_DEVICES_FILE)
    monitoring_ip = get_monitoring_device_ip()
    router_ip = get_router_ip()

    while True:
        print("\n🔄 Scanning Network for Connected Devices...\n")
        devices = get_connected_devices()

        if not devices:
            print("⚠️ No devices detected. Ensure you are connected to a network.\n")
        else:
            print("\n📡 Updated Device List (Every 10 Seconds):")

            for device in devices:
                ip = device["ip"]
                mac = device["mac"]

                # Ignore monitoring device and router
                if ip == monitoring_ip or ip == router_ip:
                    continue

                # Ensure device entry exists in detected_devices
                if mac not in detected_devices:
                    detected_devices[mac] = {"time_spent": 0, "connection_attempts": 1}
                else:
                    detected_devices[mac]["time_spent"] += SCAN_INTERVAL
                    detected_devices[mac]["connection_attempts"] += 1

                print(f"🔹 IP: {device['ip']} | MAC: {device['mac']} | Status: Active | Time Online: {detected_devices[mac]['time_spent']} sec | Attempts: {detected_devices[mac]['connection_attempts']}")

        save_json(detected_devices, DETECTED_DEVICES_FILE)
        time.sleep(SCAN_INTERVAL)

if __name__ == "__main__":
    monitor_network()
