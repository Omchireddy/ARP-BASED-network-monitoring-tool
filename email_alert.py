import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "networkmonitor404@gmail.com"
SENDER_PASSWORD = "exct ckgt fzcs olja"
RECEIVER_EMAIL = "networkmonitor404@gmail.com"

def send_alert(device):
    """Send an email alert when an external device is detected."""
    try:
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = RECEIVER_EMAIL

        if device is None:
            msg["Subject"] = "NETWORK REPORT: SAFE, NO NEW DEVICE DETECTED"
            body = "✅ Your network is safe. No external devices detected in the last 10 seconds."
        else:
            msg["Subject"] = "🚨 NETWORK ALERT: UNKNOWN DEVICE DETECTED"
            body = f"""
            ⚠️ A new device has connected to your network!

            🔹 **Device OS**: {device['os_type']}
            🔹 **Device IP**: {device['ip']}
            🔹 **MAC Address**: {device['mac']}
            🔹 **Time Spent on Network**: {device['time_spent']} sec
            🔹 **Connection Attempts**: {device['connection_attempts']}

            Please check if this connection is authorized.
            """

        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())

        print(f"📧 Email Alert Sent: {msg['Subject']}")

    except Exception as e:
        print(f"⚠️ Error Sending Email: {e}")
