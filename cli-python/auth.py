import os
import argon2

def derive_keys(master_password: str, salt: bytes) -> tuple[bytes, bytes]:
    """
    Derives two 256-bit (32-byte) keys from the master password using Argon2id.
    Argon2id is the winner of the Password Hashing Competition and recommended by OWASP.
    Returns: (encryption_key, mac_key)
    """
    # Derive a 64-byte master key
    master_key = argon2.low_level.hash_secret_raw(
        secret=master_password.encode('utf-8'),
        salt=salt,
        time_cost=3,         # 3 iterations
        memory_cost=65536,   # 64 MB of RAM
        parallelism=4,       # 4 threads
        hash_len=64,         # 64 bytes total
        type=argon2.low_level.Type.ID
    )
    
    # Split into two 32-byte keys for Encrypt-then-MAC (or just use enc_key for GCM)
    enc_key = master_key[:32]
    mac_key = master_key[32:]
    return enc_key, mac_key

def get_or_create_salt(salt_path: str) -> bytes:
    """Gets the existing salt from a file, or creates a new one if it doesn't exist."""
    if os.path.exists(salt_path):
        with open(salt_path, 'rb') as f:
            return f.read()
    else:
        # Create a new random salt (Argon2 requires minimum 8 bytes, typically 16)
        salt = os.urandom(16)
        with open(salt_path, 'wb') as f:
            f.write(salt)
        return salt
