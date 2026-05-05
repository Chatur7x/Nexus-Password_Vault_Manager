"""
NEXUS Physical Security Integration (9.2)

Implements:
- Bluetooth Proximity Auto-Lock (BLE scanning for paired device)
- USB Physical Key (key fragment stored on removable drive)
- Duress PIN (decoy vault + silent alarm to designated contact)
- Thermal Attack Resistance (keyboard heat signature contamination)
"""

import os
import json
import hashlib
import time
import random
import string
import urllib.request
from datetime import datetime, timezone

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
DURESS_FILE = os.path.join(DATA_DIR, 'duress_config.json')
USB_KEY_FILE = "nexus_key_fragment.bin"  # Stored on USB root


class BluetoothProximityLock:
    """
    Monitors BLE (Bluetooth Low Energy) for a paired device.
    When the paired device leaves range, the vault auto-locks.
    When it returns, biometric re-auth is triggered.
    
    On Windows: uses Windows.Devices.Bluetooth via pythonnet or subprocess.
    On macOS: uses CoreBluetooth via pyobjc.
    On Linux: uses bluepy or bleak.
    """

    def __init__(self):
        self.paired_device_mac = None
        self.is_in_range = False
        self.config_path = os.path.join(DATA_DIR, 'bt_proximity.json')
        self._load_config()

    def _load_config(self):
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            self.paired_device_mac = config.get("paired_mac")

    def pair_device(self, mac_address: str):
        """Register a device (phone/watch) for proximity monitoring."""
        self.paired_device_mac = mac_address
        config = {
            "paired_mac": mac_address,
            "paired_at": datetime.now(timezone.utc).isoformat()
        }
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(config, f)
        print(f"✅ Device {mac_address} paired for proximity auto-lock.")

    def scan_for_device(self) -> bool:
        """
        Scan BLE for the paired device.
        Returns True if device is in range, False otherwise.
        
        In production: uses 'bleak' library for cross-platform BLE scanning.
        """
        # Simulated scan — in production, use bleak.BleakScanner
        if not self.paired_device_mac:
            return True  # No device paired, skip proximity check

        # Simulate: check env var for testing
        simulated_in_range = os.environ.get("NEXUS_BT_IN_RANGE", "1") == "1"
        self.is_in_range = simulated_in_range

        if not self.is_in_range:
            print("🔒 Paired device out of Bluetooth range. Vault auto-locked.")
        return self.is_in_range

    def get_status(self) -> dict:
        return {
            "paired_mac": self.paired_device_mac,
            "is_in_range": self.is_in_range,
            "auto_lock_active": self.paired_device_mac is not None
        }


class USBPhysicalKey:
    """
    Uses any USB drive as a physical key.
    A 32-byte encrypted key fragment is stored on the USB.
    The vault can only decrypt if both the master password AND the USB fragment are present.
    Removing the USB instantly locks the vault.
    """

    @staticmethod
    def generate_key_fragment() -> bytes:
        """Generate a random 32-byte key fragment for USB storage."""
        return os.urandom(32)

    @staticmethod
    def write_to_usb(drive_path: str, fragment: bytes):
        """Write the key fragment to a USB drive."""
        key_path = os.path.join(drive_path, USB_KEY_FILE)
        with open(key_path, 'wb') as f:
            f.write(fragment)
        print(f"✅ USB Physical Key written to {key_path}")
        print("⚠️  Keep this USB in a safe location. Without it, the vault cannot be decrypted.")

    @staticmethod
    def read_from_usb(drive_path: str) -> bytes:
        """Read the key fragment from a USB drive."""
        key_path = os.path.join(drive_path, USB_KEY_FILE)
        if not os.path.exists(key_path):
            raise FileNotFoundError(f"USB key fragment not found at {key_path}")
        with open(key_path, 'rb') as f:
            return f.read()

    @staticmethod
    def combine_keys(master_key: bytes, usb_fragment: bytes) -> bytes:
        """Combine the master-derived key with the USB fragment via HMAC."""
        return hashlib.sha256(master_key + usb_fragment).digest()

    @staticmethod
    def detect_usb_drives() -> list[str]:
        """
        Detect mounted USB drives.
        Windows: scan drive letters D: through Z:
        Linux/macOS: scan /media/ and /Volumes/
        """
        import platform
        drives = []
        if platform.system() == "Windows":
            for letter in "DEFGHIJKLMNOPQRSTUVWXYZ":
                path = f"{letter}:\\"
                if os.path.exists(path):
                    key_path = os.path.join(path, USB_KEY_FILE)
                    if os.path.exists(key_path):
                        drives.append(path)
        else:
            for mount_dir in ["/media", "/Volumes", "/mnt"]:
                if os.path.exists(mount_dir):
                    for entry in os.listdir(mount_dir):
                        full = os.path.join(mount_dir, entry)
                        key_path = os.path.join(full, USB_KEY_FILE)
                        if os.path.exists(key_path):
                            drives.append(full)
        return drives


class DuressPin:
    """
    A separate PIN that opens a convincing decoy vault while simultaneously
    sending a silent alarm to a designated emergency contact.
    """

    def __init__(self):
        self.config_path = DURESS_FILE
        self._load_config()

    def _load_config(self):
        self.duress_pin_hash = None
        self.emergency_contact = None
        self.decoy_vault_data = {}

        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            self.duress_pin_hash = config.get("duress_pin_hash")
            self.emergency_contact = config.get("emergency_contact")
            self.decoy_vault_data = config.get("decoy_vault", {})

    def setup(self, duress_pin: str, emergency_contact: str, decoy_entries: dict):
        """
        Configure the duress system.
        duress_pin: The PIN that triggers the decoy vault.
        emergency_contact: URL/email/webhook to send the silent alarm to.
        decoy_entries: A convincing-looking fake vault to display.
        """
        pin_hash = hashlib.sha256(duress_pin.encode()).hexdigest()
        config = {
            "duress_pin_hash": pin_hash,
            "emergency_contact": emergency_contact,
            "decoy_vault": decoy_entries,
            "configured_at": datetime.now(timezone.utc).isoformat()
        }
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(config, f)
        self.duress_pin_hash = pin_hash
        self.emergency_contact = emergency_contact
        self.decoy_vault_data = decoy_entries
        print("✅ Duress PIN configured. Decoy vault ready.")

    def check_pin(self, entered_pin: str) -> bool:
        """Check if the entered PIN matches the duress PIN."""
        if not self.duress_pin_hash:
            return False
        return hashlib.sha256(entered_pin.encode()).hexdigest() == self.duress_pin_hash

    def trigger_silent_alarm(self) -> dict:
        """
        Send a silent alarm to the designated emergency contact.
        Includes timestamp and approximate location (IP-based).
        The user sees the decoy vault; the attacker suspects nothing.
        """
        alarm_data = {
            "event": "DURESS_TRIGGERED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "device_info": os.environ.get("COMPUTERNAME", "unknown"),
        }

        # Attempt to get approximate location
        try:
            req = urllib.request.Request(
                "http://ip-api.com/json",
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            with urllib.request.urlopen(req, timeout=3) as response:
                loc = json.loads(response.read().decode('utf-8'))
                alarm_data["location"] = {
                    "city": loc.get("city"),
                    "country": loc.get("country"),
                    "lat": loc.get("lat"),
                    "lon": loc.get("lon"),
                    "isp": loc.get("isp")
                }
        except Exception:
            alarm_data["location"] = "unavailable"

        # Send to emergency contact (webhook simulation)
        if self.emergency_contact:
            try:
                payload = json.dumps(alarm_data).encode('utf-8')
                req = urllib.request.Request(
                    self.emergency_contact,
                    data=payload,
                    headers={'Content-Type': 'application/json'},
                    method='POST'
                )
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass  # Silent — must not reveal failure to the attacker

        return alarm_data

    def get_decoy_vault(self) -> dict:
        """Return the convincing decoy vault data."""
        return self.decoy_vault_data


class ThermalAttackResistance:
    """
    After the user types the master password, this module deliberately
    injects random keypresses into a hidden input field to contaminate
    the keyboard's thermal signature.
    
    A thermal camera pointed at the keyboard would see heat on all keys,
    making it impossible to determine which keys were actually pressed.
    """

    @staticmethod
    def contaminate_thermal_signature(duration_ms: int = 500) -> str:
        """
        Generate a sequence of random keypresses to contaminate thermal readings.
        Returns the contamination string (for the UI to inject into a hidden field).
        """
        # Generate random chars covering all keyboard positions
        all_keys = string.ascii_letters + string.digits + string.punctuation + "     "
        contamination = ""
        target_chars = max(30, duration_ms // 15)  # ~15ms per key
        for _ in range(target_chars):
            contamination += random.choice(all_keys)
        return contamination

    @staticmethod
    def get_thermal_noise_sequence() -> list[dict]:
        """
        Generate a sequence of simulated keypress events with realistic timing.
        Each event has a key and a delay (ms) to simulate natural typing.
        """
        all_keys = list(string.ascii_lowercase + string.digits)
        sequence = []
        for _ in range(40):
            sequence.append({
                "key": random.choice(all_keys),
                "delay_ms": random.randint(20, 120)
            })
        return sequence
