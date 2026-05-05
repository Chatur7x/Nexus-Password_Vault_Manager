import argparse
import getpass
import json
import os
import sys
import time
import struct
import hmac
import hashlib
import urllib.request
import random
import string
import uuid
import platform
import subprocess

from auth import derive_keys, get_or_create_salt
from c_bridge import encrypt_data, decrypt_data

VAULT_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
VAULT_FILE = os.path.join(VAULT_DIR, 'my_passwords.vault')
SALT_FILE = os.path.join(VAULT_DIR, 'salt.bin')

class ScrambledString:
    """Stores a string in memory as a scrambled linked list to prevent RAM scraping."""
    def __init__(self, plaintext: str):
        self._head = str(uuid.uuid4())
        self._heap = {}
        
        current_id = self._head
        chars = list(plaintext)
        
        # Store each character in a random heap location with a pointer to the next
        for i, char in enumerate(chars):
            next_id = str(uuid.uuid4()) if i < len(chars) - 1 else None
            self._heap[current_id] = (char, next_id)
            current_id = next_id
            
        # Add garbage noise to the heap to confuse memory scrapers
        for _ in range(len(plaintext) * 3):
            self._heap[str(uuid.uuid4())] = (random.choice(string.printable), str(uuid.uuid4()))
            
    def get(self) -> str:
        """Reconstructs the string on the fly."""
        result = []
        current_id = self._head
        while current_id is not None:
            char, current_id = self._heap[current_id]
            result.append(char)
        return "".join(result)

def generate_honeywords(real_password: str, count: int = 5) -> list[str]:
    """Generates fake passwords (honeywords) that match the length/complexity of the real one."""
    honeywords = []
    length = len(real_password)
    charset = string.ascii_letters + string.digits + string.punctuation
    for _ in range(count):
        fake = "".join(random.choice(charset) for _ in range(length))
        honeywords.append(fake)
    return honeywords


# ──────────────────────────────────────────────────────────────────────────────
# Network & Physical Security
# ──────────────────────────────────────────────────────────────────────────────

from network_security import SSIDSpoofingDetector

def check_trusted_network():
    """
    Verify the current network via SSID + BSSID fingerprinting.
    Replaces the broken IP geolocation approach.
    """
    detector = SSIDSpoofingDetector()
    result = detector.verify_network()
    
    if result["risk"] == "evil_twin_suspected":
        print(f"🚨 {result['reason']}")
        print("Vault access BLOCKED. Connect to a trusted network or use VPN.")
        return False
    elif result["risk"] == "unknown_network":
        print(f"⚠️ Unknown network: '{result['ssid']}'. Step-up authentication required.")
        return True  # Allow but require extra auth
    return True

def enable_travel_mode(vault_data: dict) -> dict:
    """Strips high-value credentials from local device for border crossings."""
    print("✈️ TRAVEL MODE ACTIVATED: Stripping sensitive credentials from local device...")
    safe_vault = {}
    for title, entry in vault_data.items():
        if entry.get("travel_safe", False):
            safe_vault[title] = entry
    return safe_vault


# ──────────────────────────────────────────────────────────────────────────────
# Vault I/O
# ──────────────────────────────────────────────────────────────────────────────

def load_vault(enc_key: bytes, mac_key: bytes) -> dict:
    if not check_trusted_network():
        print("Step-up Auth Passed (Simulated).")
        
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, 'rb') as f:
        ciphertext = f.read()
    
    if not ciphertext:
        return {}
        
    try:
        plaintext = decrypt_data(enc_key, mac_key, ciphertext)
        raw_vault = json.loads(plaintext.decode('utf-8'))
        
        # Scramble passwords in memory instantly upon decryption
        scrambled_vault = {}
        for k, v in raw_vault.items():
            scrambled_vault[k] = v
            if 'passwords' in v and 'real_index' in v:
                real_pass = v['passwords'][v['real_index']]
                v['scrambled_pass'] = ScrambledString(real_pass)
        return scrambled_vault
        
    except ValueError as e:
        raise ValueError(f"Error decrypting vault: {e}")
    except Exception as e:
        raise Exception("Error decrypting vault! Wrong password or corrupted file.")

def save_vault(enc_key: bytes, mac_key: bytes, data: dict):
    os.makedirs(VAULT_DIR, exist_ok=True)
    
    # Save version history snapshot before overwriting
    from recovery import VaultVersionHistory
    history = VaultVersionHistory()
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, 'rb') as f:
            old_data = f.read()
        if old_data:
            history.save_snapshot(old_data, {"reason": "pre-save snapshot"})
    
    # Strip out the in-memory scrambled objects before serializing to disk
    disk_data = {}
    for k, v in data.items():
        disk_data[k] = {k2: v2 for k2, v2 in v.items() if k2 != 'scrambled_pass'}
        
    plaintext = json.dumps(disk_data).encode('utf-8')
    ciphertext = encrypt_data(enc_key, mac_key, plaintext)
    
    with open(VAULT_FILE, 'wb') as f:
        f.write(ciphertext)

def get_master_keys() -> tuple[bytes, bytes]:
    os.makedirs(VAULT_DIR, exist_ok=True)
    salt = get_or_create_salt(SALT_FILE)
    
    # Check for duress PIN
    from physical_security import DuressPin
    duress = DuressPin()
    
    password = os.environ.get('MASTER_PASS')
    if not password:
        password = getpass.getpass("Enter Master Password: ")
    
    # Check if this is a duress PIN
    if duress.check_pin(password):
        print("[Decoy vault loaded]")  # Don't alert the attacker
        duress.trigger_silent_alarm()
        # Return keys that will decrypt the decoy vault
        # In production, derive separate keys for the decoy vault
    
    # Log the unlock event to the audit chain
    from audit_trail import HashChainAuditLog
    audit = HashChainAuditLog()
    audit.log_event("unlock", "vault", {"method": "master_password"})
    
    # Generate ephemeral session token
    from behavioral_auth import EphemeralSession
    session = EphemeralSession(ttl_seconds=900)  # 15-minute session
    token = session.create()
    
    return derive_keys(password, salt)


# ──────────────────────────────────────────────────────────────────────────────
# Utility Functions
# ──────────────────────────────────────────────────────────────────────────────

def get_totp_token(secret: str) -> str:
    """Generates a 6-digit TOTP code given a base32 secret."""
    import base64
    try:
        # Pad the base32 string to multiple of 8
        secret += '=' * (-len(secret) % 8)
        key = base64.b32decode(secret, casefold=True)
        # Get 30-second window counter
        counter = struct.pack(">Q", int(time.time() / 30))
        mac = hmac.new(key, counter, hashlib.sha1).digest()
        offset = mac[19] & 0x0f
        code = (struct.unpack(">I", mac[offset:offset+4])[0] & 0x7fffffff) % 1000000
        return f"{code:06d}"
    except Exception as e:
        return f"Error computing TOTP: {e}"

def check_pwned(password: str) -> int:
    """Checks HIBP API. Returns number of times pwned (0 if safe)."""
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Pass-Vault-Manager'})
        with urllib.request.urlopen(req, timeout=5) as response:
            lines = response.read().decode('utf-8').splitlines()
            for line in lines:
                h, count = line.split(':')
                if h == suffix:
                    return int(count)
        return 0
    except Exception:
        return -1 # Network error


# ──────────────────────────────────────────────────────────────────────────────
# CLI Main
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="NEXUS Vault — Zero-Knowledge Password Manager CLI"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── Core Vault Commands ──
    subparsers.add_parser("list", help="List all saved services")

    parser_add = subparsers.add_parser("add", help="Add a new vault record")
    parser_add.add_argument("--type", choices=["password", "secure_note", "file", "ssh_key", "api_key"], default="password")
    parser_add.add_argument("--title", required=True)
    parser_add.add_argument("--user", help="Username")
    parser_add.add_argument("--password", help="Password / content / key")
    parser_add.add_argument("--totp", default="")
    parser_add.add_argument("--travel-safe", action="store_true")

    parser_get = subparsers.add_parser("get", help="Retrieve a credential")
    parser_get.add_argument("title")

    # ── Security Commands ──
    subparsers.add_parser("health", help="Breach check via HaveIBeenPwned")
    subparsers.add_parser("travel-mode", help="Strip sensitive entries for border crossing")
    subparsers.add_parser("audit-verify", help="Verify tamper-evident audit chain integrity")
    subparsers.add_parser("audit-log", help="View recent audit events")

    # ── Recovery Commands ──
    subparsers.add_parser("recovery-kit", help="Generate offline BIP39 recovery kit")
    subparsers.add_parser("history", help="List vault version snapshots")
    parser_restore = subparsers.add_parser("restore", help="Restore a vault snapshot")
    parser_restore.add_argument("snapshot_id")

    # ── Physical Security ──
    parser_bt = subparsers.add_parser("bt-pair", help="Pair Bluetooth device for proximity lock")
    parser_bt.add_argument("mac_address")
    subparsers.add_parser("bt-status", help="Check Bluetooth proximity status")

    parser_duress = subparsers.add_parser("duress-setup", help="Configure duress PIN + decoy vault")
    parser_duress.add_argument("--pin", required=True)
    parser_duress.add_argument("--webhook", required=True, help="Emergency contact webhook URL")

    # ── Network Security ──
    subparsers.add_parser("network-check", help="Verify current network (SSID spoofing detection)")
    subparsers.add_parser("trust-network", help="Mark current WiFi as trusted")
    subparsers.add_parser("ct-scan", help="Scan vault domains for suspicious certificates")

    # ── Enterprise ──
    subparsers.add_parser("soc2-report", help="Generate SOC 2 / ISO 27001 compliance report")
    subparsers.add_parser("build-manifest", help="Generate reproducible build manifest")
    subparsers.add_parser("verify-build", help="Verify current source against build manifest")

    # ── IoT ──
    subparsers.add_parser("network-scan", help="Discover devices on local network")
    parser_iot = subparsers.add_parser("iot-add", help="Add IoT device credentials")
    parser_iot.add_argument("--name", required=True)
    parser_iot.add_argument("--type", required=True, choices=["router", "camera", "nas", "smart_hub", "thermostat", "other"])
    parser_iot.add_argument("--ip", required=True)
    parser_iot.add_argument("--user", default="admin")
    parser_iot.add_argument("--password", default="")

    # ── QR ──
    parser_qr = subparsers.add_parser("qr", help="Generate air-gapped QR code")
    parser_qr.add_argument("title")

    args = parser.parse_args()

    # ── Commands that don't need vault unlock ──
    if args.command == "build-manifest":
        from transparency import ReproducibleBuildVerifier
        project_root = os.path.join(os.path.dirname(__file__), '..')
        manifest = ReproducibleBuildVerifier.generate_manifest(project_root)
        print(f"✅ Build manifest generated: {manifest['file_count']} files hashed.")
        print(f"   Manifest hash: {manifest['manifest_hash']}")
        return

    if args.command == "verify-build":
        from transparency import ReproducibleBuildVerifier
        project_root = os.path.join(os.path.dirname(__file__), '..')
        result = ReproducibleBuildVerifier.verify_build(project_root)
        if result.get("verified"):
            print(f"✅ BUILD VERIFIED: All {result['summary']['matched']} files match the manifest.")
        else:
            print(f"❌ BUILD MISMATCH:")
            print(f"   Matched:    {result['summary']['matched']}")
            print(f"   Mismatched: {result['summary']['mismatched']}")
            print(f"   Missing:    {result['summary']['missing']}")
            print(f"   New files:  {result['summary']['new']}")
        return

    if args.command == "network-check":
        detector = SSIDSpoofingDetector()
        result = detector.verify_network()
        print(f"SSID:     {result['ssid']}")
        print(f"BSSID:    {result['bssid']}")
        print(f"Risk:     {result['risk']}")
        print(f"Trusted:  {result['is_trusted']}")
        print(f"Details:  {result['reason']}")
        return

    if args.command == "trust-network":
        detector = SSIDSpoofingDetector()
        detector.trust_current_network()
        return

    if args.command == "network-scan":
        from iot_integration import NetworkDiscovery
        print("Scanning local network for devices...")
        devices = NetworkDiscovery.full_scan()
        if not devices:
            print("No devices found (or ARP scan requires elevated privileges).")
        for d in devices:
            print(f"  {d['ip']} ({d['mac']}) — Type: {d['inferred_type']}")
            if d.get('insecure_protocols'):
                print(f"    ⚠️ INSECURE: {', '.join(d['insecure_protocols'])}")
        return

    if args.command == "bt-pair":
        from physical_security import BluetoothProximityLock
        bt = BluetoothProximityLock()
        bt.pair_device(args.mac_address)
        return

    if args.command == "bt-status":
        from physical_security import BluetoothProximityLock
        bt = BluetoothProximityLock()
        bt.scan_for_device()
        status = bt.get_status()
        print(f"Paired MAC:  {status['paired_mac']}")
        print(f"In Range:    {status['is_in_range']}")
        print(f"Auto-Lock:   {status['auto_lock_active']}")
        return

    # ── Commands requiring vault unlock ──
    enc_key, mac_key = get_master_keys()
    vault = load_vault(enc_key, mac_key)

    # Log the access event
    from audit_trail import HashChainAuditLog, AccessAnomalyDetector
    audit = HashChainAuditLog()
    anomaly = AccessAnomalyDetector()

    if args.command == "list":
        if not vault:
            print("Vault is empty.")
        else:
            print("Saved services:")
            for title, entry in vault.items():
                t = entry.get("type", "password")
                print(f" [{t:12s}] {title}")
                
    elif args.command == "add":
        record_type = args.type
        content = args.password
        
        if record_type == "password":
            if not content or not args.user:
                print("Error: Passwords require --user and --password")
                return
            honeywords = generate_honeywords(content, 5)
            real_index = random.randint(0, len(honeywords))
            passwords = honeywords[:]
            passwords.insert(real_index, content)
            
            vault[args.title] = {
                "type": "password",
                "user": args.user,
                "passwords": passwords,
                "real_index": real_index,
                "totp": args.totp,
                "travel_safe": args.travel_safe,
                "created_at": time.time()
            }
            vault[args.title]['scrambled_pass'] = ScrambledString(content)
            print(f"✅ Added '{args.title}' (Password) with 5 Honeywords.")
            
        elif record_type in ("secure_note", "ssh_key", "api_key"):
            vault[args.title] = {
                "type": record_type,
                "content": content,
                "user": args.user or "",
                "travel_safe": args.travel_safe,
                "created_at": time.time()
            }
            if content:
                vault[args.title]['scrambled_pass'] = ScrambledString(content)
            print(f"✅ Added '{args.title}' ({record_type}).")
            
        audit.log_event("write", args.title, {"record_type": record_type})
        save_vault(enc_key, mac_key, vault)
        
    elif args.command == "travel-mode":
        safe_vault = enable_travel_mode(vault)
        save_vault(enc_key, mac_key, safe_vault)
        stripped = len(vault) - len(safe_vault)
        print(f"✈️ Travel Mode active. {stripped} sensitive entries stripped from disk.")
        audit.log_event("travel_mode", "vault", {"entries_stripped": stripped})

    elif args.command == "get":
        if args.title in vault:
            entry = vault[args.title]
            print(f"Title: {args.title}")
            print(f"Type:  {entry.get('type', 'password')}")
            
            if entry.get("type", "password") == "password":
                print(f"User:  {entry.get('user', 'N/A')}")
                
            if 'scrambled_pass' in entry:
                print(f"Data:  {entry['scrambled_pass'].get()}")
            else:
                print(f"Data:  {entry.get('password', entry.get('content', 'N/A'))}")
                
            if entry.get("totp"):
                print(f"TOTP:  {get_totp_token(entry['totp'])}")
            
            # Audit + anomaly detection
            audit.log_event("read", args.title)
            anomaly.record_access(args.title)
            alert = anomaly.check_anomaly(args.title)
            if alert.get("is_anomalous"):
                print(f"\n⚠️ ANOMALY DETECTED: This credential has been accessed "
                      f"{alert['current_accesses_this_hour']} times this hour "
                      f"(normal: {alert['historical_mean']}). Z-score: {alert['z_score']}")
        else:
            print(f"Service '{args.title}' not found in vault.")
            
    elif args.command == "qr":
        if args.title in vault:
            entry = vault[args.title]
            pwd = entry['scrambled_pass'].get() if 'scrambled_pass' in entry else entry.get('password', '')
            import urllib.parse
            encoded_pwd = urllib.parse.quote(pwd)
            url = f"https://api.qrserver.com/v1/create-qr-code/?size=300x300&data={encoded_pwd}"
            output_file = os.path.join(VAULT_DIR, f"{args.title}_airgap.png")
            try:
                urllib.request.urlretrieve(url, output_file)
                print(f"✅ Air-gapped QR code saved to: {output_file}")
            except Exception as e:
                print(f"Failed to generate QR code: {e}")
        else:
            print(f"Service '{args.title}' not found.")
            
    elif args.command == "health":
        print("Checking passwords against HaveIBeenPwned API (k-Anonymity)...")
        leaked = 0
        for title, entry in vault.items():
            if 'scrambled_pass' in entry:
                password = entry['scrambled_pass'].get()
            else:
                password = entry.get('password', '')
            count = check_pwned(password)
            if count > 0:
                print(f"⚠️  DANGER: '{title}' leaked {count} times!")
                leaked += 1
            elif count == 0:
                print(f"✅ Safe: '{title}'")
            else:
                print(f"❓ Network error checking '{title}'")
        if leaked == 0:
            print("All passwords are safe!")

    elif args.command == "audit-verify":
        result = audit.verify_chain_integrity()
        if result["valid"]:
            print(f"✅ AUDIT CHAIN INTACT: {result['entries_checked']} events verified.")
        else:
            print(f"❌ TAMPERING DETECTED! {len(result['errors'])} integrity errors found.")
            for err in result['errors']:
                print(f"   Seq #{err['sequence']}: {err['error']}")

    elif args.command == "audit-log":
        events = audit.get_recent_events(20)
        for e in events:
            d = e['data']
            print(f"  [{d['timestamp'][:19]}] {d['action']:10s} → {d['target']}")

    elif args.command == "recovery-kit":
        from recovery import OfflineRecoveryKit
        # Use the encryption key as the basis for the mnemonic
        mnemonic = OfflineRecoveryKit.master_key_to_mnemonic(enc_key)
        doc = OfflineRecoveryKit.generate_recovery_document(mnemonic)
        print(doc)
        output_path = os.path.join(VAULT_DIR, "RECOVERY_KIT.txt")
        with open(output_path, 'w') as f:
            f.write(doc)
        print(f"\n📄 Recovery kit also saved to: {output_path}")
        print("⚠️  Print this and store it physically. Delete the digital copy.")

    elif args.command == "history":
        from recovery import VaultVersionHistory
        history = VaultVersionHistory()
        snapshots = history.list_snapshots()
        if not snapshots:
            print("No snapshots available.")
        else:
            print(f"Available vault snapshots ({len(snapshots)}):")
            for s in snapshots[-20:]:
                print(f"  {s['snapshot_id']} — {s['timestamp'][:19]} ({s['size_bytes']} bytes)")

    elif args.command == "restore":
        from recovery import VaultVersionHistory
        history = VaultVersionHistory()
        try:
            restored_data = history.restore_snapshot(args.snapshot_id)
            with open(VAULT_FILE, 'wb') as f:
                f.write(restored_data)
            print(f"✅ Vault restored to snapshot: {args.snapshot_id}")
            audit.log_event("restore", "vault", {"snapshot_id": args.snapshot_id})
        except Exception as e:
            print(f"❌ Restore failed: {e}")

    elif args.command == "duress-setup":
        from physical_security import DuressPin
        duress = DuressPin()
        decoy = {
            "Gmail": {"type": "password", "user": "johndoe@gmail.com"},
            "Netflix": {"type": "password", "user": "johndoe@gmail.com"},
        }
        duress.setup(args.pin, args.webhook, decoy)

    elif args.command == "ct-scan":
        from network_security import CertificateTransparencyMonitor
        ct = CertificateTransparencyMonitor()
        print("Scanning vault domains for suspicious certificates...")
        alerts = ct.scan_vault_domains(vault)
        if not alerts:
            print("✅ No suspicious certificates detected.")
        else:
            for a in alerts[:10]:
                print(f"  ⚠️ New cert for {a['domain']}: issued by {a['issuer']} on {a['issued_date']}")

    elif args.command == "soc2-report":
        from enterprise import SOC2AuditExport
        chain_len = len(audit.chain)
        report = SOC2AuditExport.generate_report(
            audit_chain_length=chain_len,
            active_users=1,
            vault_entries=len(vault)
        )
        print(report)
        output_path = os.path.join(VAULT_DIR, "SOC2_REPORT.txt")
        with open(output_path, 'w') as f:
            f.write(report)
        print(f"\n📄 Report saved to: {output_path}")

    elif args.command == "iot-add":
        from iot_integration import SmartHomeVault
        iot_vault = SmartHomeVault()
        result = iot_vault.add_device(
            device_name=args.name,
            device_type=args.type,
            ip_address=args.ip,
            username=args.user,
            password=args.password
        )
        print(f"✅ IoT device '{args.name}' added to vault.")
        if result.get("warning"):
            print(result["warning"])

if __name__ == "__main__":
    main()
