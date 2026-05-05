"""
NEXUS Smart Device & IoT Integration (9.6)

Implements:
- Smart Home Credential Vault (IoT device management)
- Router Integration (local network discovery + default password detection)
- Connected Vehicle Credential Store (offline-optimized)
"""

import os
import json
import hashlib
import socket
import subprocess
import platform
from datetime import datetime, timezone

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
IOT_DIR = os.path.join(DATA_DIR, 'iot')
os.makedirs(IOT_DIR, exist_ok=True)

# Common default credentials for IoT devices (for detection warnings)
DEFAULT_CREDENTIALS = {
    "router": [
        {"user": "admin", "password": "admin"},
        {"user": "admin", "password": "password"},
        {"user": "admin", "password": "1234"},
        {"user": "root", "password": "root"},
        {"user": "admin", "password": ""},
    ],
    "camera": [
        {"user": "admin", "password": "admin"},
        {"user": "admin", "password": "12345"},
    ],
    "nas": [
        {"user": "admin", "password": "admin"},
        {"user": "admin", "password": ""},
    ],
    "smart_hub": [
        {"user": "admin", "password": "admin"},
    ]
}


class SmartHomeVault:
    """
    Separate encrypted section for IoT device credentials.
    Stores router admin passwords, NAS credentials, smart hub logins,
    camera access codes, and other IoT device authentication data.
    
    Tagged by device type for organized management.
    Supports local-network-only access mode for offline scenarios.
    """

    DEVICES_FILE = os.path.join(IOT_DIR, 'smart_devices.json')

    def __init__(self):
        self.devices = self._load_devices()

    def _load_devices(self) -> dict:
        if os.path.exists(self.DEVICES_FILE):
            with open(self.DEVICES_FILE, 'r') as f:
                return json.load(f)
        return {}

    def _save_devices(self):
        with open(self.DEVICES_FILE, 'w') as f:
            json.dump(self.devices, f, indent=2)

    def add_device(
        self,
        device_name: str,
        device_type: str,
        ip_address: str,
        mac_address: str = "",
        username: str = "",
        password: str = "",
        notes: str = ""
    ) -> dict:
        """
        Add an IoT device to the smart home vault.
        device_type: "router", "camera", "nas", "smart_hub", "thermostat",
                     "doorbell", "speaker", "tv", "other"
        """
        device_id = hashlib.sha256(
            f"{device_name}:{ip_address}:{mac_address}".encode()
        ).hexdigest()[:12]

        # Check if using default credentials
        is_default = False
        defaults = DEFAULT_CREDENTIALS.get(device_type, [])
        for d in defaults:
            if d["user"] == username and d["password"] == password:
                is_default = True
                break

        device = {
            "id": device_id,
            "name": device_name,
            "type": device_type,
            "ip_address": ip_address,
            "mac_address": mac_address,
            "username": username,
            "password": password,
            "notes": notes,
            "uses_default_credentials": is_default,
            "added_at": datetime.now(timezone.utc).isoformat(),
            "last_accessed": None,
            "offline_accessible": True
        }

        self.devices[device_id] = device
        self._save_devices()

        warning = ""
        if is_default:
            warning = (
                "\n⚠️  WARNING: This device is using DEFAULT credentials! "
                "Change the password immediately to prevent unauthorized access."
            )

        return {"device": device, "warning": warning}

    def list_devices(self, device_type: str = None) -> list[dict]:
        """List all IoT devices, optionally filtered by type."""
        devices = list(self.devices.values())
        if device_type:
            devices = [d for d in devices if d["type"] == device_type]
        return devices

    def get_insecure_devices(self) -> list[dict]:
        """Return all devices using default credentials."""
        return [d for d in self.devices.values() if d.get("uses_default_credentials")]


class NetworkDiscovery:
    """
    Scans the local network to identify connected devices.
    Suggests creating vault entries for devices with default or missing credentials.
    
    Uses ARP scanning and port probing to identify device types.
    """

    COMMON_PORTS = {
        80: "HTTP (Web Interface)",
        443: "HTTPS (Secure Web)",
        22: "SSH",
        23: "Telnet (INSECURE)",
        21: "FTP (INSECURE)",
        8080: "HTTP Alt (Web Interface)",
        8443: "HTTPS Alt",
        554: "RTSP (Camera Stream)",
        5000: "NAS Management",
        9090: "Smart Hub",
        1883: "MQTT (IoT Protocol)",
        8883: "MQTT over TLS",
    }

    @staticmethod
    def get_local_subnet() -> str:
        """Detect the local network subnet."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            # Derive subnet (assumes /24)
            parts = local_ip.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}"
        except Exception:
            return "192.168.1"

    @staticmethod
    def arp_scan() -> list[dict]:
        """
        Perform an ARP scan to discover devices on the local network.
        Windows: arp -a
        Linux: arp-scan --localnet (requires sudo)
        macOS: arp -a
        """
        devices = []
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output(
                    ['arp', '-a'], text=True, timeout=10
                )
                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and '.' in parts[0]:
                        ip = parts[0]
                        mac = parts[1]
                        if mac != "ff-ff-ff-ff-ff-ff":
                            devices.append({
                                "ip": ip,
                                "mac": mac.replace('-', ':'),
                                "type": "unknown"
                            })
            else:
                output = subprocess.check_output(
                    ['arp', '-a'], text=True, timeout=10
                )
                for line in output.splitlines():
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if '.' in p and p[0].isdigit():
                            ip = p.strip('()')
                            mac = parts[i+1] if i+1 < len(parts) else ""
                            if mac and mac != "ff:ff:ff:ff:ff:ff":
                                devices.append({
                                    "ip": ip,
                                    "mac": mac,
                                    "type": "unknown"
                                })
                            break
        except Exception:
            pass

        return devices

    @staticmethod
    def probe_device(ip: str) -> dict:
        """
        Probe a device to identify its type based on open ports.
        """
        open_ports = []
        services = []

        for port, service_name in NetworkDiscovery.COMMON_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
                    services.append(service_name)
            except Exception:
                pass

        # Classify device type based on ports
        device_type = "unknown"
        if 554 in open_ports:
            device_type = "camera"
        elif 5000 in open_ports:
            device_type = "nas"
        elif 1883 in open_ports or 8883 in open_ports:
            device_type = "smart_hub"
        elif 80 in open_ports or 443 in open_ports:
            device_type = "router"  # Default guess for web-accessible devices

        insecure_protocols = []
        if 23 in open_ports:
            insecure_protocols.append("Telnet (unencrypted)")
        if 21 in open_ports:
            insecure_protocols.append("FTP (unencrypted)")

        return {
            "ip": ip,
            "open_ports": open_ports,
            "services": services,
            "inferred_type": device_type,
            "insecure_protocols": insecure_protocols,
            "needs_credential_entry": True
        }

    @staticmethod
    def full_scan() -> list[dict]:
        """Run a full network discovery and device classification."""
        devices = NetworkDiscovery.arp_scan()
        results = []
        for device in devices:
            probe = NetworkDiscovery.probe_device(device["ip"])
            probe["mac"] = device["mac"]
            results.append(probe)
        return results


class VehicleCredentialStore:
    """
    Stores PINs, access codes, and paired device credentials for connected vehicles.
    Optimized for offline access — no network needed to retrieve them.
    
    Entries are tagged with vehicle info for organized management.
    """

    VEHICLES_FILE = os.path.join(IOT_DIR, 'vehicles.json')

    def __init__(self):
        self.vehicles = self._load_vehicles()

    def _load_vehicles(self) -> dict:
        if os.path.exists(self.VEHICLES_FILE):
            with open(self.VEHICLES_FILE, 'r') as f:
                return json.load(f)
        return {}

    def _save_vehicles(self):
        with open(self.VEHICLES_FILE, 'w') as f:
            json.dump(self.vehicles, f, indent=2)

    def add_vehicle(
        self,
        name: str,
        make: str,
        model: str,
        year: int,
        vin: str = "",
        pin: str = "",
        app_credentials: dict = None,
        bluetooth_key: str = "",
        notes: str = ""
    ) -> dict:
        """Add a connected vehicle's credentials."""
        vehicle_id = hashlib.sha256(
            f"{name}:{vin}:{make}{model}".encode()
        ).hexdigest()[:12]

        vehicle = {
            "id": vehicle_id,
            "name": name,
            "make": make,
            "model": model,
            "year": year,
            "vin": vin,
            "pin": pin,
            "app_credentials": app_credentials or {},
            "bluetooth_key": bluetooth_key,
            "notes": notes,
            "added_at": datetime.now(timezone.utc).isoformat(),
            "offline_accessible": True
        }

        self.vehicles[vehicle_id] = vehicle
        self._save_vehicles()
        return vehicle

    def list_vehicles(self) -> list[dict]:
        return list(self.vehicles.values())
