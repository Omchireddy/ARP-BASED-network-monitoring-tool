import sys
import os
import time
import json
import platform
import subprocess
import socket
import re
import threading
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout, 
                            QHBoxLayout, QTableWidget, QTableWidgetItem, QLabel, 
                            QPushButton, QLineEdit, QComboBox, QCheckBox, QGroupBox,
                            QFormLayout, QMessageBox, QProgressBar, QTextEdit, QSplitter,
                            QDialog, QDialogButtonBox, QMenu, QAction)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QColor, QIcon
import scapy.all as scapy

# Configuration
CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "SMTP_SERVER": "smtp.gmail.com",
    "SMTP_PORT": 587,
    "EMAIL_SENDER": "networkmonitor404@gmail.com",
    "EMAIL_PASSWORD": "your_app_password",  # Use an app password for Gmail
    "EMAIL_RECEIVER": "networkmonitor404@gmail.com",
    "NETWORK_INTERFACE": "Wi-Fi",
    "SCAN_INTERVAL": 20,
    "EMAIL_ALERTS_ENABLED": True,
    "ALERT_NEW_DEVICES": True,
    "ALERT_SUSPICIOUS": True,
}

# Load configuration
def load_config():
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        else:
            with open(CONFIG_FILE, "w") as f:
                json.dump(DEFAULT_CONFIG, f, indent=4)
            return DEFAULT_CONFIG
    except Exception as e:
        print(f"Error loading config: {e}")
        return DEFAULT_CONFIG

CONFIG = load_config()

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

# Email alert function
def send_alert(device=None):
    """Send an email alert when an external device is detected."""
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    
    try:
        msg = MIMEMultipart()
        msg["From"] = CONFIG["EMAIL_SENDER"]
        msg["To"] = CONFIG["EMAIL_RECEIVER"]

        if device is None:
            msg["Subject"] = "NETWORK REPORT: SAFE, NO NEW DEVICE DETECTED"
            body = "✅ Your network is safe. No external devices detected in the last scan."
        else:
            msg["Subject"] = "🚨 NETWORK ALERT: UNKNOWN DEVICE DETECTED"
            body = f"""
            ⚠️ A new device has connected to your network!

            🔹 **Device OS**: {device.get('os_type', 'Unknown')}
            🔹 **Device IP**: {device.get('ip', 'Unknown')}
            🔹 **MAC Address**: {device.get('mac', 'Unknown')}
            🔹 **Time Spent on Network**: {device.get('time_spent', 0)} sec
            🔹 **Connection Attempts**: {device.get('connection_attempts', 0)}

            Please check if this connection is authorized.
            """

        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(CONFIG["SMTP_SERVER"], CONFIG["SMTP_PORT"]) as server:
            server.starttls()
            server.login(CONFIG["EMAIL_SENDER"], CONFIG["EMAIL_PASSWORD"])
            server.sendmail(CONFIG["EMAIL_SENDER"], CONFIG["EMAIL_RECEIVER"], msg.as_string())

        print(f"📧 Email Alert Sent: {msg['Subject']}")
        return True
    except Exception as e:
        print(f"⚠️ Error Sending Email: {e}")
        return False

class AdvancedFilterDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Advanced Filter")
        self.setGeometry(300, 300, 500, 300)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Protocol selection
        protocol_group = QGroupBox("Protocol")
        protocol_layout = QHBoxLayout(protocol_group)
        
        self.tcp_checkbox = QCheckBox("TCP")
        self.udp_checkbox = QCheckBox("UDP")
        self.icmp_checkbox = QCheckBox("ICMP")
        self.arp_checkbox = QCheckBox("ARP")
        
        protocol_layout.addWidget(self.tcp_checkbox)
        protocol_layout.addWidget(self.udp_checkbox)
        protocol_layout.addWidget(self.icmp_checkbox)
        protocol_layout.addWidget(self.arp_checkbox)
        
        layout.addWidget(protocol_group)
        
        # IP filtering
        ip_group = QGroupBox("IP Address")
        ip_layout = QFormLayout(ip_group)
        
        self.src_ip_input = QLineEdit()
        self.dst_ip_input = QLineEdit()
        
        ip_layout.addRow("Source IP:", self.src_ip_input)
        ip_layout.addRow("Destination IP:", self.dst_ip_input)
        
        layout.addWidget(ip_group)
        
        # Port filtering
        port_group = QGroupBox("Port")
        port_layout = QFormLayout(port_group)
        
        self.src_port_input = QLineEdit()
        self.dst_port_input = QLineEdit()
        
        port_layout.addRow("Source Port:", self.src_port_input)
        port_layout.addRow("Destination Port:", self.dst_port_input)
        
        layout.addWidget(port_group)
        
        # Advanced filter (raw BPF)
        advanced_group = QGroupBox("Raw BPF Filter")
        advanced_layout = QVBoxLayout(advanced_group)
        
        self.advanced_filter_input = QLineEdit()
        self.advanced_filter_input.setPlaceholderText("e.g., 'tcp port 80 and host 192.168.1.100'")
        advanced_layout.addWidget(self.advanced_filter_input)
        
        layout.addWidget(advanced_group)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    
    
    def get_filter(self):
        # Build filter string from UI elements
        filter_parts = []
        
        # Protocol filters
        protocols = []
        if self.tcp_checkbox.isChecked():
            protocols.append("tcp")
        if self.udp_checkbox.isChecked():
            protocols.append("udp")
        if self.icmp_checkbox.isChecked():
            protocols.append("icmp")
        if self.arp_checkbox.isChecked():
            protocols.append("arp")
            
        if protocols:
            filter_parts.append(f"({' or '.join(protocols)})")
        
        # IP filters
        src_ip = self.src_ip_input.text().strip()
        dst_ip = self.dst_ip_input.text().strip()
        
        if src_ip:
            filter_parts.append(f"src host {src_ip}")
        if dst_ip:
            filter_parts.append(f"dst host {dst_ip}")
            
        # Port filters
        src_port = self.src_port_input.text().strip()
        dst_port = self.dst_port_input.text().strip()
        
        if src_port:
            filter_parts.append(f"src port {src_port}")
        if dst_port:
            filter_parts.append(f"dst port {dst_port}")
            
        # Advanced filter (raw BPF)
        advanced_filter = self.advanced_filter_input.text().strip()
        if advanced_filter:
            return advanced_filter
            
        # Combine all parts
        return " and ".join(filter_parts) if filter_parts else ""

class PacketCaptureThread(QThread):
    packet_captured = pyqtSignal(dict)
    
    def __init__(self, interface, filter_text=""):
        super().__init__()
        self.interface = interface
        self.filter_text = filter_text
        self.running = True
        
    def run(self):
        def packet_callback(packet):
            if not self.running:
                return
                
            # Extract basic packet info
            packet_info = {
                "time": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "src_ip": packet[scapy.IP].src if scapy.IP in packet else "N/A",
                "dst_ip": packet[scapy.IP].dst if scapy.IP in packet else "N/A",
                "protocol": self.get_protocol(packet),
                "length": len(packet),
                "src_mac": packet.src if hasattr(packet, 'src') else "N/A",
                "dst_mac": packet.dst if hasattr(packet, 'dst') else "N/A",
                "info": self.get_packet_info(packet),
                "raw_packet": packet  # Store the raw packet for detailed view
            }
            self.packet_captured.emit(packet_info)
            
        try:
            scapy.sniff(iface=self.interface, filter=self.filter_text, prn=packet_callback, store=0)
        except Exception as e:
            print(f"Error in packet capture: {e}")
            
    def stop(self):
        self.running = False
        self.terminate()
        
    def update_filter(self, filter_text):
        self.filter_text = filter_text
        self.stop()
        self.start()
        
    def get_protocol(self, packet):
        if scapy.TCP in packet:
            return "TCP"
        elif scapy.UDP in packet:
            return "UDP"
        elif scapy.ICMP in packet:
            return "ICMP"
        elif scapy.ARP in packet:
            return "ARP"
        else:
            return "Other"
            
    def get_packet_info(self, packet):
        if scapy.TCP in packet:
            sport = packet[scapy.TCP].sport
            dport = packet[scapy.TCP].dport
            flags = self.get_tcp_flags(packet[scapy.TCP].flags)
            return f"TCP {sport} → {dport} [Flags: {flags}]"
        elif scapy.UDP in packet:
            sport = packet[scapy.UDP].sport
            dport = packet[scapy.UDP].dport
            return f"UDP {sport} → {dport}"
        elif scapy.ICMP in packet:
            return f"ICMP {packet[scapy.ICMP].type}/{packet[scapy.ICMP].code}"
        elif scapy.ARP in packet:
            return f"ARP {packet[scapy.ARP].op} {packet[scapy.ARP].psrc} → {packet[scapy.ARP].pdst}"
        else:
            return "Unknown packet type"
            
    def get_tcp_flags(self, flags):
        flag_str = ""
        if flags & 0x01:  # FIN
            flag_str += "F"
        if flags & 0x02:  # SYN
            flag_str += "S"
        if flags & 0x04:  # RST
            flag_str += "R"
        if flags & 0x08:  # PSH
            flag_str += "P"
        if flags & 0x10:  # ACK
            flag_str += "A"
        if flags & 0x20:  # URG
            flag_str += "U"
        return flag_str if flag_str else "None"

class DeviceScannerThread(QThread):
    device_found = pyqtSignal(dict)
    scan_complete = pyqtSignal()
    
    def __init__(self, interval=CONFIG["SCAN_INTERVAL"]):
        super().__init__()
        self.interval = interval
        self.running = True
        
    def run(self):
        while self.running:
            devices = self.get_connected_devices()
            for device in devices:
                self.device_found.emit(device)
            self.scan_complete.emit()
            time.sleep(self.interval)
            
    def stop(self):
        self.running = False
        
    def get_monitoring_device_ip(self):
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception as e:
            print(f"Error fetching monitoring device IP: {e}")
            return None
            
    def get_router_ip(self):
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output("ipconfig", shell=True, text=True)
                for line in output.split("\n"):
                    if "Default Gateway" in line:
                        return line.split(":")[-1].strip()
            elif platform.system() == "Linux":
                output = subprocess.check_output("ip route", shell=True, text=True)
                return output.split()[2] if "default via" in output else None
            return None
        except Exception as e:
            print(f"Error fetching router IP: {e}")
            return None
            
    def get_connected_devices(self):
        devices = {}
        try:
            if platform.system() == "Windows":
                arp_output = subprocess.check_output("arp -a", shell=True, text=True)
                ip_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([a-fA-F0-9:-]+)")
            
                for line in arp_output.split("\n"):
                    match = ip_pattern.search(line)
                    if match:
                        ip, mac = match.groups()
                        if mac != "ff-ff-ff-ff-ff-ff":  # Ignore broadcast
                            devices[ip] = {"ip": ip, "mac": mac, "status": "Active"}
            elif platform.system() == "Linux":
                arp_output = subprocess.check_output("arp -n", shell=True, text=True)
                ip_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+([a-fA-F0-9:]+)")
            
                for line in arp_output.split("\n"):
                    match = ip_pattern.search(line)
                    if match:
                        ip, mac = match.groups()
                        devices[ip] = {"ip": ip, "mac": mac, "status": "Active"}
        except subprocess.CalledProcessError as e:
            print(f"Error executing ARP command: {e}")
        except Exception as e:
         print(f"Error scanning devices: {e}")
        
        return list(devices.values())

class NetworkMonitorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Monitor")
        self.setGeometry(100, 100, 1200, 800)
        self.detected_devices = self.load_json("detected_devices.json")
        self.known_devices = self.load_json("known_devices.json")
        self.monitoring_ip = self.get_monitoring_device_ip()
        self.router_ip = self.get_router_ip()
        self.packet_capture_thread = None
        self.device_scanner_thread = None
        self.captured_packets = []  # Store captured packets for filtering
        
        self.setup_ui()
        self.start_device_scanning()
    
    def get_monitoring_device_ip(self):
        """Get the IP address of the monitoring device."""
        try:
            hostname = socket.gethostname()  # Get the hostname
            ip_address = socket.gethostbyname(hostname)  # Get the IP address
            return ip_address
        except Exception as e:
            print(f"Error fetching monitoring device IP: {e}")
            return None
        
    def get_router_ip(self):
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
            print(f"Error fetching router IP: {e}")
            return None
    def scan_now(self):
        """Manually trigger a network scan."""
        if self.device_scanner_thread is not None:
            self.device_scanner_thread.stop()  # Stop any ongoing scan
        self.device_scanner_thread = DeviceScannerThread()
        self.device_scanner_thread.device_found.connect(self.update_device_list)
        self.device_scanner_thread.scan_complete.connect(self.update_scan_complete)
        self.device_scanner_thread.start()
    def show_device_details(self):
        """Show details of the selected device."""
        selected_row = self.device_table.currentRow()
        if selected_row >= 0:
            ip_address = self.device_table.item(selected_row, 0).text()
            mac_address = self.device_table.item(selected_row, 1).text()
            # You can add more details as needed
            details = f"IP Address: {ip_address}\nMAC Address: {mac_address}\n"
            # You can fetch more details from your known_devices or detected_devices if needed
            self.device_details.setPlainText(details)
    def update_scan_complete(self):
        """Handle actions after a scan is complete."""
        print("Scan complete.")
        QMessageBox.information(self, "Scan Complete", "The device scan has been completed.")
    def toggle_packet_capture(self):
        """Start or stop packet capture."""
        if self.packet_capture_thread is None:
            self.start_packet_capture()
        else:
            self.stop_packet_capture()
    def apply_filter(self):
        """Apply the filter from the input field."""
        filter_text = self.filter_input.text().strip()
        if self.packet_capture_thread:
            self.packet_capture_thread.update_filter(filter_text)
    def show_advanced_filter(self):
        """Show the advanced filter dialog."""
        dialog = AdvancedFilterDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            filter_text = dialog.get_filter()
            if self.packet_capture_thread:
                self.packet_capture_thread.update_filter(filter_text)
    def apply_preset_filter(self):
        """Apply a preset filter based on the selected option."""
        preset = self.preset_combo.currentText()
        if preset == "Show All":
            self.filter_input.setText("")
        elif preset == "TCP Only":
            self.filter_input.setText("tcp")
        elif preset == "UDP Only":
            self.filter_input.setText("udp")
        elif preset == "ICMP Only":
            self.filter_input.setText("icmp")
        elif preset == "ARP":
            self.filter_input.setText("arp")
        elif preset == "HTTP/HTTPS":
            self.filter_input.setText("tcp port 80 or tcp port 443")
        elif preset == "DNS":
            self.filter_input.setText("udp port 53")
        elif preset == "Common Ports":
            self.filter_input.setText("tcp port 22 or tcp port 80 or tcp port 443")
    
        self.apply_filter()
    def show_packet_details(self):
        """Show details of the selected packet."""
        selected_row = self.packet_table.currentRow()
        if selected_row >= 0:
            packet_info = self.captured_packets[selected_row]
            self.packet_details.setPlainText(str(packet_info))

    def add_trusted_device(self):
        """Add the selected device to trusted devices."""
        selected_row = self.device_table.currentRow()
        if selected_row >= 0:
            mac_address = self.device_table.item(selected_row, 1).text()
            self.known_devices[mac_address] = True
            self.save_json(self.known_devices, "known_devices.json")
            QMessageBox.information(self, "Success", f"Device {mac_address} added to trusted devices.")
    def mark_suspicious_device(self):
        """Mark the selected device as suspicious."""
        selected_row = self.device_table.currentRow()
        if selected_row >= 0:
            mac_address = self.device_table.item(selected_row, 1).text()
            # Implement your logic to mark the device as suspicious
            QMessageBox.warning(self, "Suspicious Device", f"Device {mac_address} marked as suspicious.")
    def send_report(self):
        """Send a network report via email."""
        # Implement your logic to send a report
        QMessageBox.information(self, "Report", "Network report sent successfully.")
    def save_general_settings(self):
        """Save the general settings."""
        CONFIG["SCAN_INTERVAL"] = int(self.scan_interval_input.text().strip())
        CONFIG["NETWORK_INTERFACE"] = self.interface_combo.currentText()
        save_config(CONFIG)
        QMessageBox.information(self, "Success", "General settings saved successfully.")
    def save_email_settings(self):
        """Save the email settings."""
        CONFIG["SMTP_SERVER"] = self.smtp_server_input.text().strip()
        CONFIG["SMTP_PORT"] = int(self.smtp_port_input.text().strip())
        CONFIG["EMAIL_SENDER"] = self.email_sender_input.text().strip()
        CONFIG["EMAIL_PASSWORD"] = self.email_password_input.text().strip()
        CONFIG["EMAIL_RECEIVER"] = self.email_input.text().strip()
        save_config(CONFIG)
        QMessageBox.information(self, "Success", "Email settings saved successfully.")
    def setup_ui(self):
        # Create central widget and tab structure
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_packet_capture_tab()
        self.create_device_monitor_tab()
        self.create_alerts_tab()
        self.create_settings_tab()
        
        # Status bar
        self.statusBar().showMessage("Ready")
        
    def create_dashboard_tab(self):
        dashboard_tab = QWidget()
        layout = QVBoxLayout(dashboard_tab)
        
        # Summary section
        summary_group = QGroupBox("Network Summary")
        summary_layout = QVBoxLayout(summary_group)
        
        self.active_devices_label = QLabel("Active Devices: 0")
        self.active_devices_label.setFont(QFont("Arial", 12))
        summary_layout.addWidget(self.active_devices_label)
        
        self.network_status_label = QLabel("Network Status: Monitoring")
        self.network_status_label.setFont(QFont("Arial", 12))
        summary_layout.addWidget(self.network_status_label)
        
        layout.addWidget(summary_group)
        
        # Quick actions section
        actions_group = QGroupBox("Quick Actions")
        actions_layout = QHBoxLayout(actions_group)
        
        scan_now_btn = QPushButton("Scan Network")
        scan_now_btn.clicked.connect(self.scan_now)
        actions_layout.addWidget(scan_now_btn)
        
        start_capture_btn = QPushButton("Start Packet Capture")
        start_capture_btn.clicked.connect(self.toggle_packet_capture)
        self.start_capture_btn = start_capture_btn
        actions_layout.addWidget(start_capture_btn)
        
        send_report_btn = QPushButton("Send Network Report")
        send_report_btn.clicked.connect(self.send_report)
        actions_layout.addWidget(send_report_btn)
        
        layout.addWidget(actions_group)
        
        # Recent activity section
        activity_group = QGroupBox("Recent Activity")
        activity_layout = QVBoxLayout(activity_group)
        
        self.activity_text = QTextEdit()
        self.activity_text.setReadOnly(True)
        activity_layout.addWidget(self.activity_text)
        
        layout.addWidget(activity_group)
        
        self.tabs.addTab(dashboard_tab, "Dashboard")
        
    def create_packet_capture_tab(self):
        packet_tab = QWidget()
        layout = QVBoxLayout(packet_tab)
        
        # Filter section
        filter_group = QGroupBox("Packet Filters")
        filter_layout = QVBoxLayout(filter_group)
        
        # Basic filter row
        basic_filter_layout = QHBoxLayout()
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Enter filter (e.g., 'tcp port 80' or 'host 192.168.1.1')")
        basic_filter_layout.addWidget(self.filter_input)
        
        filter_btn = QPushButton("Apply Filter")
        filter_btn.clicked.connect(self.apply_filter)
        basic_filter_layout.addWidget(filter_btn)
        
        advanced_filter_btn = QPushButton("Advanced Filter")
        advanced_filter_btn.clicked.connect(self.show_advanced_filter)
        basic_filter_layout.addWidget(advanced_filter_btn)
        
        filter_layout.addLayout(basic_filter_layout)
        
        # Preset filters
        preset_layout = QHBoxLayout()
        preset_label = QLabel("Presets:")
        preset_layout.addWidget(preset_label)
        
        preset_filters = [
            "Show All", 
            "TCP Only", 
            "UDP Only", 
            "ICMP Only", 
            "ARP", 
            "HTTP/HTTPS", 
            "DNS", 
            "Common Ports"
        ]
        self.preset_combo = QComboBox()
        self.preset_combo.addItems(preset_filters)
        preset_layout.addWidget(self.preset_combo)
        
        preset_apply_btn = QPushButton("Apply Preset")
        preset_apply_btn.clicked.connect(self.apply_preset_filter)
        preset_layout.addWidget(preset_apply_btn)
        
        filter_layout.addLayout(preset_layout)
        layout.addWidget(filter_group)
        
        # Packet capture and details splitter
        splitter = QSplitter(Qt.Vertical)
        
        # Packet capture table
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(8)
        self.packet_table.setHorizontalHeaderLabels([
            "Time", "Source IP", "Destination IP", 
            "Protocol", "Length", "Source MAC", 
            "Destination MAC", "Info"
        ])
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.packet_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.packet_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.packet_table.customContextMenuRequested.connect(self.show_packet_context_menu)
        self.packet_table.itemSelectionChanged.connect(self.show_packet_details)
        splitter.addWidget(self.packet_table)
        
        # Packet details
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        details_layout.setContentsMargins(0, 0, 0, 0)
        
        self.packet_details = QTextEdit()
        self.packet_details.setReadOnly(True)
        details_layout.addWidget(self.packet_details)
        
        splitter.addWidget(details_widget)
        splitter.setSizes([500, 300])  # Initial sizes
        
        layout.addWidget(splitter)
        
        self.tabs.addTab(packet_tab, "Packet Capture")
        
    def create_device_monitor_tab(self):
        device_tab = QWidget()
        layout = QVBoxLayout(device_tab)
        
        # Device list
        device_list_group = QGroupBox("Connected Devices")
        device_list_layout = QVBoxLayout(device_list_group)
        
        self.device_table = QTableWidget()
        self.device_table.setColumnCount(5)
        self.device_table.setHorizontalHeaderLabels([
            "IP Address", "MAC Address", "Status", 
            "Time Online", "Connection Attempts"
        ])
        self.device_table.horizontalHeader().setStretchLastSection(True)
        self.device_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.device_table.itemSelectionChanged.connect(self.show_device_details)
        self.device_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.device_table.customContextMenuRequested.connect(self.show_device_context_menu)
        device_list_layout.addWidget(self.device_table)
        
        layout.addWidget(device_list_group)
        
        # Device details
        device_details_group = QGroupBox("Device Details")
        device_details_layout = QVBoxLayout(device_details_group)
        
        self.device_details = QTextEdit()
        self.device_details.setReadOnly(True)
        device_details_layout.addWidget(self.device_details)
        
        layout.addWidget(device_details_group)
        
        # Device actions
        actions_layout = QHBoxLayout()
        
        add_trusted_btn = QPushButton("Add to Trusted Devices")
        add_trusted_btn.clicked.connect(self.add_trusted_device)
        actions_layout.addWidget(add_trusted_btn)
        
        mark_suspicious_btn = QPushButton("Mark as Suspicious")
        mark_suspicious_btn.clicked.connect(self.mark_suspicious_device)
        actions_layout.addWidget(mark_suspicious_btn)
        
        layout.addLayout(actions_layout)
        
        self.tabs.addTab(device_tab, "Device Monitor")
        
    def create_alerts_tab(self):
        alerts_tab = QWidget()
        layout = QVBoxLayout(alerts_tab)
        
        # Alert settings
        alert_settings_group = QGroupBox("Alert Settings")
        alert_settings_layout = QFormLayout(alert_settings_group)
        
        self.email_alerts_checkbox = QCheckBox("Enable Email Alerts")
        self.email_alerts_checkbox.setChecked(CONFIG.get("EMAIL_ALERTS_ENABLED", True))
        alert_settings_layout.addRow("Email Alerts:", self.email_alerts_checkbox)
        
        self.email_input = QLineEdit(CONFIG.get("EMAIL_RECEIVER", ""))
        alert_settings_layout.addRow("Email Address:", self.email_input)
        
        self.alert_new_devices_checkbox = QCheckBox("Alert on New Devices")
        self.alert_new_devices_checkbox.setChecked(CONFIG.get("ALERT_NEW_DEVICES", True))
        alert_settings_layout.addRow("New Devices:", self.alert_new_devices_checkbox)
        
        self.alert_suspicious_checkbox = QCheckBox("Alert on Suspicious Activity")
        self.alert_suspicious_checkbox.setChecked(CONFIG.get("ALERT_SUSPICIOUS", True))
        alert_settings_layout.addRow("Suspicious Activity:", self.alert_suspicious_checkbox)
        
        save_alert_settings_btn = QPushButton("Save Alert Settings")
        save_alert_settings_btn.clicked.connect(self.save_alert_settings)
        alert_settings_layout.addWidget(save_alert_settings_btn)
        
        layout.addWidget(alert_settings_group)
        
        # Alert history
        alert_history_group = QGroupBox("Alert History")
        alert_history_layout = QVBoxLayout(alert_history_group)
        
        self.alert_table = QTableWidget()
        self.alert_table.setColumnCount(4)
        self.alert_table.setHorizontalHeaderLabels(["Time", "Type", "Device", "Description"])
        self.alert_table.horizontalHeader().setStretchLastSection(True)
        self.alert_table.setSelectionBehavior(QTableWidget.SelectRows)
        alert_history_layout.addWidget(self.alert_table)
        
        clear_alerts_btn = QPushButton("Clear Alert History")
        clear_alerts_btn.clicked.connect(self.clear_alert_history)
        alert_history_layout.addWidget(clear_alerts_btn)
        
        layout.addWidget(alert_history_group)
        
        self.tabs.addTab(alerts_tab, "Alerts")
        
    def create_settings_tab(self):
        settings_tab = QWidget()
        layout = QVBoxLayout(settings_tab)
        
        # General settings
        general_settings_group = QGroupBox("General Settings")
        general_settings_layout = QFormLayout(general_settings_group)
        
        self.scan_interval_input = QLineEdit(str(CONFIG.get("SCAN_INTERVAL", 20)))
        general_settings_layout.addRow("Scan Interval (seconds):", self.scan_interval_input)
        
        # Get available network interfaces
        interfaces = self.get_network_interfaces()
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(interfaces)
        current_interface = CONFIG.get("NETWORK_INTERFACE", "")
        if current_interface in interfaces:
            self.interface_combo.setCurrentText(current_interface)
        general_settings_layout.addRow("Network Interface:", self.interface_combo)
        
        save_general_settings_btn = QPushButton("Save General Settings")
        save_general_settings_btn.clicked.connect(self.save_general_settings)
        general_settings_layout.addWidget(save_general_settings_btn)
        
        layout.addWidget(general_settings_group)
        
        # Email settings
        email_settings_group = QGroupBox("Email Settings")
        email_settings_layout = QFormLayout(email_settings_group)
        
        self.smtp_server_input = QLineEdit(CONFIG.get("SMTP_SERVER", "smtp.gmail.com"))
        email_settings_layout.addRow("SMTP Server:", self.smtp_server_input)
        
        self.smtp_port_input = QLineEdit(str(CONFIG.get("SMTP_PORT", 587)))
        email_settings_layout.addRow("SMTP Port:", self.smtp_port_input)
        
        self.email_sender_input = QLineEdit(CONFIG.get("EMAIL_SENDER", ""))
        email_settings_layout.addRow("Sender Email:", self.email_sender_input)
        
        self.email_password_input = QLineEdit(CONFIG.get("EMAIL_PASSWORD", ""))
        self.email_password_input.setEchoMode(QLineEdit.Password)
        email_settings_layout.addRow("Password:", self.email_password_input)
        
        test_email_btn = QPushButton("Test Email Settings")
        test_email_btn.clicked.connect(self.test_email_settings)
        email_settings_layout.addWidget(test_email_btn)
        
        save_email_settings_btn = QPushButton("Save Email Settings")
        save_email_settings_btn.clicked.connect(self.save_email_settings)
        email_settings_layout.addWidget(save_email_settings_btn)
        
        layout.addWidget(email_settings_group)
        
        # Advanced settings
        advanced_settings_group = QGroupBox("Advanced Settings")
        advanced_settings_layout = QVBoxLayout(advanced_settings_group)
        
        export_data_btn = QPushButton("Export Data")
        export_data_btn.clicked.connect(self.export_data)
        advanced_settings_layout.addWidget(export_data_btn)
        
        clear_data_btn = QPushButton("Clear All Data")
        clear_data_btn.clicked.connect(self.clear_data)
        advanced_settings_layout.addWidget(clear_data_btn)
        
        layout.addWidget(advanced_settings_group)
        
        self.tabs.addTab(settings_tab, "Settings")
        
    def load_json(self, file_path):
        """Load JSON data from a file."""
        try:
            with open(file_path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
            
    def save_json(self, data, file_path):
        """Save JSON data to a file."""
        with open(file_path, "w") as f:
            json.dump(data, f)
    
    def start_device_scanning(self):
        """Start the device scanning thread."""
        self.device_scanner_thread = DeviceScannerThread()
        self.device_scanner_thread.device_found.connect(self.update_device_list)
        self.device_scanner_thread.scan_complete.connect(self.update_scan_complete)
        self.device_scanner_thread.start()
        
    def update_device_list(self, device):
        """Update the device list in the UI."""
        # Add device to the table
        row_position = self.device_table.rowCount()
        self.device_table.insertRow(row_position)
        self.device_table.setItem(row_position, 0, QTableWidgetItem(device["ip"]))
        self.device_table.setItem(row_position, 1, QTableWidgetItem(device["mac"]))
        self.device_table.setItem(row_position, 2, QTableWidgetItem(device["status"]))
        self.device_table.setItem(row_position, 3, QTableWidgetItem("N/A"))  # Time Online
        self.device_table.setItem(row_position, 4, QTableWidgetItem("1"))  # Connection Attempts
        
        # Update active devices count
        active_devices_count = self.device_table.rowCount()
        self.active_devices_label.setText(f"Active Devices: {active_devices_count}")
        
    def update_scan_complete(self):
        """Handle actions after a scan is complete."""
        print("Scan complete.")
        
    def apply_filter(self):
        """Apply the filter from the input field."""
        filter_text = self.filter_input.text().strip()
        if self.packet_capture_thread:
            self.packet_capture_thread.update_filter(filter_text)
        
    def show_advanced_filter(self):
        """Show the advanced filter dialog."""
        dialog = AdvancedFilterDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            filter_text = dialog.get_filter()
            if self.packet_capture_thread:
                self.packet_capture_thread.update_filter(filter_text)
        
    def apply_preset_filter(self):
        """Apply a preset filter based on the selected option."""
        preset = self.preset_combo.currentText()
        if preset == "Show All":
            self.filter_input.setText("")
        elif preset == "TCP Only":
            self.filter_input.setText("tcp")
        elif preset == "UDP Only":
            self.filter_input.setText("udp")
        elif preset == "ICMP Only":
            self.filter_input.setText("icmp")
        elif preset == "ARP":
            self.filter_input.setText("arp")
        elif preset == "HTTP/HTTPS":
            self.filter_input.setText("tcp port 80 or tcp port 443")
        elif preset == "DNS":
            self.filter_input.setText("udp port 53")
        elif preset == "Common Ports":
            self.filter_input.setText("tcp port 22 or tcp port 80 or tcp port 443")
        
        self.apply_filter()
        
    def show_packet_context_menu(self, pos):
        """Show context menu for packet table."""
        menu = QMenu(self)
        view_details_action = QAction("View Details", self)
        view_details_action.triggered.connect(self.show_packet_details)
        menu.addAction(view_details_action)
        menu.exec_(self.packet_table.viewport().mapToGlobal(pos))
        
    def show_packet_details(self):
        """Show details of the selected packet."""
        selected_row = self.packet_table.currentRow()
        if selected_row >= 0:
            packet_info = self.captured_packets[selected_row]
            self.packet_details.setPlainText(str(packet_info))
        
    def show_device_context_menu(self, pos):
        """Show context menu for device table."""
        menu = QMenu(self)
        add_trusted_action = QAction("Add to Trusted Devices", self)
        add_trusted_action.triggered.connect(self.add_trusted_device)
        menu.addAction(add_trusted_action)
        
        mark_suspicious_action = QAction("Mark as Suspicious", self)
        mark_suspicious_action.triggered.connect(self.mark_suspicious_device)
        menu.addAction(mark_suspicious_action)
        
        menu.exec_(self.device_table.viewport().mapToGlobal(pos))
        
    def add_trusted_device(self):
        """Add the selected device to trusted devices."""
        selected_row = self.device_table.currentRow()
        if selected_row >= 0:
            mac_address = self.device_table.item(selected_row, 1).text()
            self.known_devices[mac_address] = True
            self.save_json(self.known_devices, "known_devices.json")
            QMessageBox.information(self, "Success", f"Device {mac_address} added to trusted devices.")
        
    def mark_suspicious_device(self):
        """Mark the selected device as suspicious."""
        selected_row = self.device_table.currentRow()
        if selected_row >= 0:
            mac_address = self.device_table.item(selected_row, 1).text()
            # Implement your logic to mark the device as suspicious
            QMessageBox.warning(self, "Suspicious Device", f"Device {mac_address} marked as suspicious.")
        
    def send_report(self):
        """Send a network report via email."""
        # Implement your logic to send a report
        QMessageBox.information(self, "Report", "Network report sent successfully.")
        
    def toggle_packet_capture(self):
        """Start or stop packet capture."""
        if self.packet_capture_thread is None:
            self.start_packet_capture()
        else:
            self.stop_packet_capture()
        
    def start_packet_capture(self):
        """Start the packet capture thread."""
        interface = self.interface_combo.currentText()
        filter_text = self.filter_input.text().strip()
        self.packet_capture_thread = PacketCaptureThread(interface, filter_text)
        self.packet_capture_thread.packet_captured.connect(self.update_packet_list)
        self.packet_capture_thread.start()
        self.start_capture_btn.setText("Stop Packet Capture")
        
    def stop_packet_capture(self):
        """Stop the packet capture thread."""
        if self.packet_capture_thread:
            self.packet_capture_thread.stop()
            self.packet_capture_thread = None
            self.start_capture_btn.setText("Start Packet Capture")
        
    def update_packet_list(self, packet_info):
        """Update the packet list in the UI."""
        self.captured_packets.append(packet_info)
        row_position = self.packet_table.rowCount()
        self.packet_table.insertRow(row_position)
        self.packet_table.setItem(row_position, 0, QTableWidgetItem(packet_info["time"]))
        self.packet_table.setItem(row_position, 1, QTableWidgetItem(packet_info["src_ip"]))
        self .packet_table.setItem(row_position, 2, QTableWidgetItem(packet_info["dst_ip"]))
        self.packet_table.setItem(row_position, 3, QTableWidgetItem(packet_info["protocol"]))
        self.packet_table.setItem(row_position, 4, QTableWidgetItem(str(packet_info["length"])))
        self.packet_table.setItem(row_position, 5, QTableWidgetItem(packet_info["src_mac"]))
        self.packet_table.setItem(row_position, 6, QTableWidgetItem(packet_info["dst_mac"]))
        self.packet_table.setItem(row_position, 7, QTableWidgetItem(packet_info["info"]))
        
    def test_email_settings(self):
        """Test the email settings by sending a test email."""
        test_device = {
            "os_type": "Test OS",
            "ip": "192.168.1.1",
            "mac": "00:00:00:00:00:00",
            "time_spent": 0,
            "connection_attempts": 0
        }
        if send_alert(test_device):
            QMessageBox.information(self, "Success", "Test email sent successfully.")
        else:
            QMessageBox.warning(self, "Error", "Failed to send test email.")
        
    def save_alert_settings(self):
        """Save the alert settings."""
        CONFIG["EMAIL_ALERTS_ENABLED"] = self.email_alerts_checkbox.isChecked()
        CONFIG["ALERT_NEW_DEVICES"] = self.alert_new_devices_checkbox.isChecked()
        CONFIG["ALERT_SUSPICIOUS"] = self.alert_suspicious_checkbox.isChecked()
        CONFIG["EMAIL_RECEIVER"] = self.email_input.text().strip()
        save_config(CONFIG)
        QMessageBox.information(self, "Success", "Alert settings saved successfully.")
        
    def clear_alert_history(self):
        """Clear the alert history."""
        self.alert_table.setRowCount(0)
        QMessageBox.information(self, "Success", "Alert history cleared.")
        
    def export_data(self):
        """Export data to a file."""
        # Implement your logic to export data
        QMessageBox.information(self, "Export", "Data exported successfully.")
        
    def clear_data(self):
        """Clear all data."""
        self.detected_devices = {}
        self.known_devices = {}
        self.save_json(self.detected_devices, "detected_devices.json")
        self.save_json(self.known_devices, "known_devices.json")
        QMessageBox.information(self, "Success", "All data cleared.")

    def get_network_interfaces(self):
        """Get a list of available network interfaces."""
        interfaces = []
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output("ipconfig", shell=True, text=True)
                for line in output.split("\n"):
                    if "adapter" in line.lower():
                        interfaces.append(line.split(":")[0].strip())
            elif platform.system() == "Linux":
                output = subprocess.check_output("ifconfig", shell=True, text=True)
                for line in output.split("\n"):
                    if line and not line.startswith(" "):
                        interfaces.append(line.split(":")[0].strip())
        except Exception as e:
            print(f"Error fetching network interfaces: {e}")
        return interfaces

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkMonitorApp()
    window.show()
    sys.exit(app.exec_())