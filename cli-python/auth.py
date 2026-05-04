import hashlib
import os

def derive_keys(master_password: str, salt: bytes) -> tuple[bytes, bytes]:
    """
    Derives two 256-bit (32-byte) keys from the master password using scrypt.
    Scrypt is memory-hard, making it highly resistant to GPU cracking.
    Returns: (encryption_key, mac_key)
    """
    # Derive a 64-byte master key
    master_key = hashlib.scrypt(
        master_password.encode('utf-8'),
        salt=salt,
        n=16384, # CPU/Memory cost factor
        r=8,     # Block size
        p=1,     # Parallelization factor
        maxmem=0,
        dklen=64 # 64 bytes total
    )
    
    # Split into two 32-byte keys for Encrypt-then-MAC
    enc_key = master_key[:32]
    mac_key = master_key[32:]
    return enc_key, mac_key

def get_or_create_salt(salt_path: str) -> bytes:
    """Gets the existing salt from a file, or creates a new one if it doesn't exist."""
    if os.path.exists(salt_path):
        with open(salt_path, 'rb') as f:
            return f.read()
    else:
        # Create a new random salt
        salt = os.urandom(16)
        with open(salt_path, 'wb') as f:
            f.write(salt)
        return salt

