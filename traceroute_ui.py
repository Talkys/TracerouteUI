import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QPushButton, QListWidget, QListWidgetItem)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QPixmap, QFont
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import cartopy.crs as ccrs
import cartopy.feature as cfeature
import socket
import platform
import sys
from typing import List, Tuple, Optional
import subprocess
import requests
import re

def run_traceroute(target: str) -> List[str]:
    """
    Run traceroute command appropriate for the current OS
    and return the output lines.
    """
    try:
        if platform.system() == "Windows":
            # Windows tracert command
            result = subprocess.run(['tracert', '-d', target],
                                   capture_output=True, text=True, timeout=300)
        else:
            # Unix-like systems (Linux/macOS)
            try:
                # Try Linux traceroute first
                result = subprocess.run(['traceroute', '-n', target],
                                      capture_output=True, text=True, timeout=300)
            except FileNotFoundError:
                # Try macOS traceroute if Linux version not found
                result = subprocess.run(['traceroute', '-n', target],
                                      capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            return result.stdout.splitlines()
        else:
            print(f"Traceroute failed with return code {result.returncode}")
            print(result.stderr)
            return []
    except subprocess.TimeoutExpired:
        print("Traceroute timed out after 30 seconds")
        return []
    except Exception as e:
        print(f"Error running traceroute: {e}")
        return []

def extract_ips(traceroute_output: List[str]) -> List[str]:
    """
    Extract IP addresses from traceroute output, handling different OS formats
    """
    ips = []
    ip_pattern = r'(?:^|(?<=\s))((([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))|((25[0-5]|(2[0-4]|1[0-9]|[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1[0-9]|[0-9])?[0-9]))(?=\s|$)'
    
    for line in traceroute_output:
        # Skip header lines and empty lines
        if not line.strip() or 'traceroute' in line.lower() or 'tracert' in line.lower():
            continue
            
        # Find all IPs in the line
        found_ips = re.findall(ip_pattern, line)
        if found_ips:
            # The first IP is typically the hop IP (except on Windows where it might be the hop number)
            # Windows format:  1     2 ms     2 ms     2 ms  192.168.1.1
            # Unix format: 1  192.168.1.1 (192.168.1.1)  2.345 ms
            if platform.system() == "Windows":
                # For Windows, the IP is the last element in the line
                hop_ip = found_ips[-1]
            else:
                # For Unix, the first IP is the hop
                hop_ip = found_ips[0]
                
            if hop_ip not in ips:  # Avoid duplicates
                ips.append(hop_ip)
    
    return ips

def get_geolocation(ip: str) -> Optional[Tuple[float, float]]:
    """
    Get latitude and longitude for an IP address using ip-api.com
    Returns (lat, lon) or None if lookup fails
    """
    try:
        # Skip private IPs
        if ip.startswith(('10.', '192.168.', '172.16.', '169.254.')):
            return None
            
        response = requests.get(f'http://ip-api.com/json/{ip}?fields=status,message,lat,lon', timeout=5)
        data = response.json()
        
        if data.get('status') == 'success':
            return (data['lat'], data['lon'])
        else:
            print(f"Could not geolocate {ip}: {data.get('message', 'Unknown error')}")
            return None
    except Exception as e:
        print(f"Error geolocating {ip}: {e}")
        return None

def plot_traceroute(coords: List[Tuple[float, float]], target: str, your_location: Optional[Tuple[float, float]] = None):
    """
    Plot the traceroute coordinates on a map with the given style
    """
    if not coords:
        print("No coordinates to plot")
        return

    # Create figure with dark background
    fig = plt.figure(figsize=(12, 8), facecolor='black')
    ax = fig.add_subplot(1, 1, 1, projection=ccrs.PlateCarree())

    # Customize map colors
    ax.set_facecolor('#0a0a1a')  # Space-like dark blue
    ax.add_feature(cfeature.LAND, color='#2d2d4d')  # Dark land
    ax.add_feature(cfeature.OCEAN, color='#111133')  # Deep ocean
    ax.add_feature(cfeature.COASTLINE, linewidth=0.5, edgecolor='#aaaaaa')
    ax.add_feature(cfeature.BORDERS, linestyle=':', edgecolor='#666666')

    ax.set_global()  # Forces the map to show the entire world

    # Plot traceroute path with glowing effect
    lats, lons = zip(*coords)
    ax.plot(lons, lats, '-', color='cyan', linewidth=1, alpha=0.5, transform=ccrs.Geodetic())

    # Add glowing markers
    for i, (lat, lon) in enumerate(coords):
        # Make the start and end points larger
        size = 12 if i == 0 or i == len(coords)-1 else 8
        ax.plot(lon, lat, 'o', color='white', markersize=size+2, transform=ccrs.Geodetic())
        ax.plot(lon, lat, 'o', color='cyan', markersize=size, transform=ccrs.Geodetic())

    # Add labels for start and end points
    if your_location:
        ax.text(your_location[1], your_location[0], 'You', color='white', ha='right', va='bottom', transform=ccrs.Geodetic())
    ax.text(lons[-1], lats[-1], target, color='white', ha='left', va='bottom', transform=ccrs.Geodetic())

    # Title
    plt.title(f'Traceroute to {target}', color='white', pad=20)

    # Save or show
    output_file = f'traceroute_{target}.png'
    plt.savefig(output_file, dpi=600, bbox_inches='tight', facecolor=fig.get_facecolor())
    print(f"Map saved to {output_file}")
    plt.show()

def get_your_location() -> Optional[Tuple[float, float]]:
    """Try to determine the user's location using a public IP service"""
    try:
        response = requests.get('https://ipapi.co/json/', timeout=5)
        data = response.json()
        return (data['latitude'], data['longitude'])
    except Exception as e:
        print(f"Could not determine your location: {e}")
        return None

# Import your existing traceroute functions here (keep all the original imports and functions)
# ... [all your existing imports and functions] ...

class TracerouteWorker(QThread):
    update_signal = pyqtSignal(list, object, str)  # coords, your_location, target_ip
    ip_signal = pyqtSignal(list)  # list of IPs
    error_signal = pyqtSignal(str)  # error message
    
    def __init__(self, target):
        super().__init__()
        self.target = target
    
    def run(self):
        try:
            # Resolve hostname to IP for the output filename
            try:
                target_ip = socket.gethostbyname(self.target)
            except socket.gaierror:
                target_ip = self.target
            
            traceroute_output = run_traceroute(self.target)
            
            if not traceroute_output:
                self.error_signal.emit("No traceroute output received")
                return
            
            ips = extract_ips(traceroute_output)
            
            if not ips:
                self.error_signal.emit("No IP addresses found in traceroute output")
                return
            
            # Clean up IPs if they're tuples
            for i in range(len(ips)):
                if isinstance(ips[i], tuple):
                    ips[i] = max(ips[i], key=len)
            
            self.ip_signal.emit(ips)
            
            # Look up geographic locations
            coords = []
            your_location = get_your_location()
            
            for ip in ips:
                location = get_geolocation(ip)
                if location:
                    coords.append(location)
            
            if len(coords) < 2:
                self.error_signal.emit("Need at least 2 locations to plot a path")
                return
            
            # Emit the signal with your_location (which might be None)
            self.update_signal.emit(coords, your_location, target_ip)
            
        except Exception as e:
            self.error_signal.emit(f"Error: {str(e)}")

class MapCanvas(FigureCanvas):
    def __init__(self, parent=None, width=8, height=6, dpi=100):
        self.fig = plt.figure(figsize=(width, height), facecolor='black')
        self.ax = self.fig.add_subplot(1, 1, 1, projection=ccrs.PlateCarree())
        super().__init__(self.fig)
        self.setParent(parent)
        self.clear_map()
    
    def clear_map(self):
        """Initialize an empty map"""
        self.ax.clear()
        self.ax.set_facecolor('#0a0a1a')  # Space-like dark blue
        self.ax.add_feature(cfeature.LAND, color='#2d2d4d')  # Dark land
        self.ax.add_feature(cfeature.OCEAN, color='#111133')  # Deep ocean
        self.ax.add_feature(cfeature.COASTLINE, linewidth=0.5, edgecolor='#aaaaaa')
        self.ax.add_feature(cfeature.BORDERS, linestyle=':', edgecolor='#666666')
        self.ax.set_global()
        self.figure.tight_layout(pad=0)
        self.figure.subplots_adjust(left=0, right=1, top=1, bottom=0)
        self.draw()
    
    def update_map(self, coords, your_location, target):
        """Update the map with traceroute data"""
        self.ax.clear()
        self.ax.set_facecolor('#0a0a1a')
        self.ax.add_feature(cfeature.LAND, color='#2d2d4d')
        self.ax.add_feature(cfeature.OCEAN, color='#111133')
        self.ax.add_feature(cfeature.COASTLINE, linewidth=0.5, edgecolor='#aaaaaa')
        self.ax.add_feature(cfeature.BORDERS, linestyle=':', edgecolor='#666666')
        self.ax.set_global()
        
        # Plot traceroute path with glowing effect
        lats, lons = zip(*coords)
        self.ax.plot(lons, lats, '-', color='cyan', linewidth=1, alpha=0.5, transform=ccrs.Geodetic())

        # Add glowing markers
        for i, (lat, lon) in enumerate(coords):
            # Make the start and end points larger
            size = 12 if i == 0 or i == len(coords)-1 else 8
            self.ax.plot(lon, lat, 'o', color='white', markersize=size+2, transform=ccrs.Geodetic())
            self.ax.plot(lon, lat, 'o', color='cyan', markersize=size, transform=ccrs.Geodetic())

        # Add labels for start and end points
        if your_location:  # Only add "You" label if location was found
            self.ax.text(your_location[1], your_location[0], 'You', color='white', 
                        ha='right', va='bottom', transform=ccrs.Geodetic())
        self.ax.text(lons[-1], lats[-1], target, color='white', 
                    ha='left', va='bottom', transform=ccrs.Geodetic())

        # Title
        self.ax.set_title(f'Traceroute to {target}', color='white', pad=20)

        self.figure.tight_layout(pad=0)
        self.figure.subplots_adjust(left=0, right=1, top=1, bottom=0)
        
        self.draw()

class TracerouteApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Traceroute Visualizer")
        self.setGeometry(100, 100, 1200, 800)
        
        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)
        
        # Map area (left side)
        self.map_canvas = MapCanvas(self, width=8, height=6)
        main_layout.addWidget(self.map_canvas, stretch=3)
        
        # Sidebar (right side)
        sidebar = QWidget()
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(10, 10, 10, 10)
        sidebar_layout.setSpacing(15)
        
        # Target input
        target_label = QLabel("Target Hostname or IP:")
        target_label.setStyleSheet("color: white;")
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g., google.com or 8.8.8.8")
        self.target_input.setStyleSheet("""
            QLineEdit {
                background-color: #333344;
                color: white;
                border: 1px solid #555566;
                padding: 5px;
                border-radius: 4px;
            }
        """)
        
        # Start button
        self.start_button = QPushButton("Start Traceroute")
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #555555;
            }
        """)
        self.start_button.clicked.connect(self.start_traceroute)
        
        # IP List
        ip_list_label = QLabel("Traceroute Hops:")
        ip_list_label.setStyleSheet("color: white;")
        self.ip_list = QListWidget()
        self.ip_list.setStyleSheet("""
            QListWidget {
                background-color: #222233;
                color: white;
                border: 1px solid #444455;
                border-radius: 4px;
            }
        """)
        
        # Status label
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #AAAAFF;")
        self.status_label.setWordWrap(True)
        
        # Add widgets to sidebar
        sidebar_layout.addWidget(target_label)
        sidebar_layout.addWidget(self.target_input)
        sidebar_layout.addWidget(self.start_button)
        sidebar_layout.addWidget(ip_list_label)
        sidebar_layout.addWidget(self.ip_list, stretch=1)
        sidebar_layout.addWidget(self.status_label)
        
        main_layout.addWidget(sidebar, stretch=1)
        
        # Set dark theme for the main window
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a1a2e;
            }
            QLabel {
                color: white;
            }
        """)
        
        # Thread for traceroute
        self.worker = None
    
    def start_traceroute(self):
        target = self.target_input.text().strip()
        if not target:
            self.status_label.setText("Please enter a target hostname or IP")
            return
        
        # Clear previous results
        self.ip_list.clear()
        self.map_canvas.clear_map()
        self.status_label.setText(f"Running traceroute to {target}...")
        self.start_button.setEnabled(False)
        
        # Start the worker thread
        self.worker = TracerouteWorker(target)
        self.worker.update_signal.connect(self.update_map)
        self.worker.ip_signal.connect(self.update_ip_list)
        self.worker.error_signal.connect(self.show_error)
        self.worker.finished.connect(self.on_traceroute_finished)
        self.worker.start()
    
    def update_map(self, coords, your_location, target_ip):
        self.map_canvas.update_map(coords, your_location, target_ip)
        self.status_label.setText(f"Traceroute complete. Showing path to {target_ip}")
    
    def update_ip_list(self, ips):
        self.ip_list.clear()
        for ip in ips:
            item = QListWidgetItem(ip)
            item.setFlags(item.flags() | Qt.ItemIsSelectable | Qt.ItemIsEnabled)
            self.ip_list.addItem(item)
    
    def show_error(self, message):
        print(message)
        self.status_label.setText(message)
    
    def on_traceroute_finished(self):
        self.start_button.setEnabled(True)
        if self.worker:
            self.worker.deleteLater()
            self.worker = None
    
    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            self.worker.terminate()
            self.worker.wait()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern style
    
    # Set dark palette
    palette = app.palette()
    palette.setColor(palette.Window, Qt.darkGray)
    palette.setColor(palette.WindowText, Qt.white)
    palette.setColor(palette.Base, Qt.black)
    palette.setColor(palette.AlternateBase, Qt.darkGray)
    palette.setColor(palette.ToolTipBase, Qt.white)
    palette.setColor(palette.ToolTipText, Qt.white)
    palette.setColor(palette.Text, Qt.white)
    palette.setColor(palette.Button, Qt.darkGray)
    palette.setColor(palette.ButtonText, Qt.white)
    palette.setColor(palette.BrightText, Qt.red)
    palette.setColor(palette.Link, Qt.cyan)
    palette.setColor(palette.Highlight, Qt.cyan)
    palette.setColor(palette.HighlightedText, Qt.black)
    app.setPalette(palette)
    
    window = TracerouteApp()
    window.show()
    sys.exit(app.exec_())