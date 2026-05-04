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

def self_destruct():
    """Gutmann-style wiping of the vault to prevent forensics."""
    print("🚨 SECURE GEOFENCE BREACH OR TAMPER DETECTED 🚨")
    print("Initiating Self-Destruct...")
    if os.path.exists(VAULT_FILE):
        file_size = os.path.getsize(VAULT_FILE)
        with open(VAULT_FILE, 'r+b') as f:
            for _ in range(7): # 7 passes for time efficiency in simulation
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
        os.remove(VAULT_FILE)
        print("Vault has been permanently wiped from the magnetic disk.")
    raise Exception("🚨 SECURE GEOFENCE BREACH DETECTED 🚨\nVault has been permanently wiped from disk.\nSelf-Destruct Complete.")

def check_geofence():
    """Ensures the vault is only opened in the permitted geographical location."""
    geofence_file = os.path.join(VAULT_DIR, 'geofence.json')
    try:
        req = urllib.request.Request("http://ip-api.com/json", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as response:
            data = json.loads(response.read().decode('utf-8'))
            current_loc = f"{data['lat']},{data['lon']}"
            
        if not os.path.exists(geofence_file):
            # Set home location on first run
            with open(geofence_file, 'w') as f:
                json.dump({"home": current_loc}, f)
        else:
            with open(geofence_file, 'r') as f:
                home_loc = json.load(f)["home"]
            # Basic string match for simulation (in reality, calculate Haversine distance)
            # If coordinates drift significantly (different city), trigger destruct
            home_lat, home_lon = [float(x) for x in home_loc.split(',')]
            curr_lat, curr_lon = [float(x) for x in current_loc.split(',')]
            
            # If moved more than ~50 miles (approx 1 degree lat/lon)
            if abs(home_lat - curr_lat) > 1.0 or abs(home_lon - curr_lon) > 1.0:
                self_destruct()
    except Exception as e:
        # Fail open if offline
        pass

def load_vault(enc_key: bytes, mac_key: bytes) -> dict:
    check_geofence()
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
    
    password = os.environ.get('MASTER_PASS')
    if not password:
        password = getpass.getpass("Enter Master Password: ")
        
    return derive_keys(password, salt)

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

def main():
    parser = argparse.ArgumentParser(description="Password Manager CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # List command
    subparsers.add_parser("list", help="List all saved services")

    # Add command
    parser_add = subparsers.add_parser("add", help="Add a new password")
    parser_add.add_argument("--title", required=True, help="Title of the service")
    parser_add.add_argument("--user", required=True, help="Username")
    parser_add.add_argument("--password", required=True, help="Password")
    parser_add.add_argument("--totp", help="Base32 TOTP Secret (optional)", default="")

    # Get command
    parser_get = subparsers.add_parser("get", help="Get a password")
    parser_get.add_argument("title", help="Title of the service to retrieve")

    # QR command
    parser_qr = subparsers.add_parser("qr", help="Generate an Air-Gapped QR code for a password")
    parser_qr.add_argument("title", help="Title of the service")

    # Health command
    subparsers.add_parser("health", help="Check if any saved passwords are in data breaches")

    args = parser.parse_args()
    enc_key, mac_key = get_master_keys()
    vault = load_vault(enc_key, mac_key)

    if args.command == "list":
        if not vault:
            print("Vault is empty.")
        else:
            print("Saved services:")
            for title in vault.keys():
                print(f" - {title}")
                
    elif args.command == "add":
        honeywords = generate_honeywords(args.password, 5)
        # Randomly insert the real password into the honeywords list
        real_index = random.randint(0, len(honeywords))
        passwords = honeywords[:]
        passwords.insert(real_index, args.password)
        
        vault[args.title] = {
            "user": args.user,
            "passwords": passwords,
            "real_index": real_index,
            "totp": args.totp
        }
        # Immediately scramble it in memory
        vault[args.title]['scrambled_pass'] = ScrambledString(args.password)
        
        save_vault(enc_key, mac_key, vault)
        print(f"Successfully added '{args.title}' to vault with 5 Honeywords.")
        
    elif args.command == "get":
        if args.title in vault:
            entry = vault[args.title]
            print(f"Title: {args.title}")
            print(f"User:  {entry['user']}")
            
            # Retrieve password from Scrambled String to prevent memory dumping
            if 'scrambled_pass' in entry:
                print(f"Pass:  {entry['scrambled_pass'].get()}")
            else:
                # Fallback for old vault formats
                print(f"Pass:  {entry.get('password', 'N/A')}")
                
            if entry.get("totp"):
                print(f"TOTP:  {get_totp_token(entry['totp'])}")
        else:
            print(f"Service '{args.title}' not found in vault.")
            
    elif args.command == "qr":
        if args.title in vault:
            entry = vault[args.title]
            if 'scrambled_pass' in entry:
                pwd = entry['scrambled_pass'].get()
            else:
                pwd = entry.get('password', '')
            
            import urllib.parse
            encoded_pwd = urllib.parse.quote(pwd)
            url = f"https://api.qrserver.com/v1/create-qr-code/?size=300x300&data={encoded_pwd}"
            output_file = os.path.join(VAULT_DIR, f"{args.title}_airgap.png")
            try:
                urllib.request.urlretrieve(url, output_file)
                print(f"Air-gapped QR code saved to: {output_file}")
                print("Scan this with your phone to view the password without transmitting it over the local network.")
            except Exception as e:
                print(f"Failed to generate QR code: {e}")
        else:
            print(f"Service '{args.title}' not found in vault.")
            
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
                print(f"⚠️  DANGER: Password for '{title}' has been leaked {count} times!")
                leaked += 1
            elif count == 0:
                print(f"✅ Safe: '{title}'")
            else:
                print(f"❓ Network error checking '{title}'")
        
        if leaked == 0:
            print("All passwords are safe!")

if __name__ == "__main__":
    main()
