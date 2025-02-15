from wifi_scanner import scan_wifi
from scanner import monitor_network

if __name__ == "__main__":
    scan_wifi()
    input("\n🔗 Connect to your target network and press Enter to continue...")
    monitor_network()
