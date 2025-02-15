# ARP-Based Network Monitoring Tool 🚀🔍  

## Overview  
The **ARP-Based Network Monitoring Tool** is a lightweight yet powerful solution designed to enhance network security by detecting unauthorized devices and tracking network intrusions in real-time. This tool enables network administrators to monitor active connections, identify unknown devices, and receive automated alerts to mitigate potential threats.  

## 🔑 Key Features  
- **Real-time ARP Scanning:** Continuously detects all connected devices within the network.  
- **Intrusion Detection:** Identifies unauthorized devices attempting to connect.  
- **Automated Email Notifications:** Sends instant alerts when an unknown device is detected.  
- **Device Tracking:** Monitors and logs how long a device remains connected.  
- **Historical Logging System:** Maintains a detailed log of all detected devices for future analysis.  
- **Lightweight and Efficient:** Uses ARP scanning instead of deep packet inspection, ensuring minimal resource usage.  

## ⚙️ How It Works  
1. **Sends ARP Requests:** The tool periodically sends ARP requests to identify active devices within the network.  
2. **Maintains a Device List:** Stores known devices to differentiate between authorized and unauthorized connections.  
3. **Continuous Monitoring:** Runs in a loop to constantly scan for new device connections.  
4. **Triggers Alerts:** Immediately sends an email notification if an unknown device is detected.  
5. **Sends ‘Safe’ Status Updates:** If no new devices are detected, the tool sends a status email every 10 seconds.  

## 🛠️ Installation Guide  
### **Step 1: Clone the Repository**  
```bash  
git clone https://github.com/your-username/ARP-Network-Monitoring-Tool.git  
cd ARP-Network-Monitoring-Tool  
```

### **Step 2: Install Required Dependencies**  
Ensure you have Python installed, then install the necessary libraries:  
```bash  
pip install scapy smtplib schedule  
```

### **Step 3: Configure Email Alerts**  
Edit the script to include your email credentials for sending notifications. Update the following lines in `config.py`:  
```python  
EMAIL_SENDER = "your-email@example.com"  
EMAIL_PASSWORD = "your-password"  
EMAIL_RECEIVER = "admin@example.com"  
```

### **Step 4: Run the Monitoring Tool**  
```bash  
python monitor.py  
```

## 🔍 Use Cases  
- **Enterprise Networks:** Monitor internal networks and detect unauthorized connections.  
- **Home Security:** Ensure only trusted devices are connected to your personal network.  
- **Educational Institutions:** Protect institutional networks from external intrusions.  
- **Cybersecurity Research:** Analyze network behavior and security threats.  

## 🚀 Future Enhancements  
- **User-Friendly GUI:** Develop a graphical interface for intuitive monitoring.  
- **Database Integration:** Store device logs for long-term analysis.  
- **AI-Driven Threat Detection:** Implement machine learning models to detect anomalies.  
- **Customizable Alerts:** Allow users to define alert preferences and thresholds.  

## 📧 Contributions & Feedback  
We welcome contributions! Feel free to fork this repository, submit pull requests, or open issues. Let’s work together to strengthen network security!  

For inquiries or collaboration, contact us at **omchireddy2004@gmail.com**.  

---  
**Developed by:** Sai Om Chi Reddy  
**License:** MIT  
