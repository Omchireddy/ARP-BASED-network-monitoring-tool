import subprocess
import re

def scan_wifi():
    """Lists available Wi-Fi networks on Windows."""
    print("\n📡 Scanning for available Wi-Fi networks...\n")

    try:
        # Ensure proper encoding to avoid UnicodeDecodeError
        result = subprocess.run(
            ["netsh", "wlan", "show", "network"],
            capture_output=True,
            text=True,
            encoding="utf-8",  # Force UTF-8 encoding
            errors="ignore"  # Ignore invalid characters
        )

        # Ensure stdout is not None before processing
        if result.stdout is None:
            print("❌ Error: Failed to retrieve Wi-Fi networks.")
            return []

        # Extract SSID (network names) using regex
        networks = re.findall(r"SSID \d+ : (.+)", result.stdout)

        if networks:
            print("📶 Available Networks:\n")
            for i, network in enumerate(networks, start=1):
                print(f"{i}. {network}")
            return networks
        else:
            print("❌ No Wi-Fi networks found.")
            return []

    except subprocess.CalledProcessError as e:
        print(f"⚠️ Error scanning networks: {e}")
        return []

if __name__ == "__main__":
    scan_wifi()
