import sys
from PyQt5.QtWidgets import QApplication
from gui import NetworkMonitorApp  # Assuming your GUI code is in gui.py

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkMonitorApp()
    window.show()
    sys.exit(app.exec_())