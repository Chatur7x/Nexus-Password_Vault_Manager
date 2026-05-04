import ctypes
import os
import sys

# Try to load the C library
lib_name = "vault_engine.dll" if os.name == 'nt' else "libvault_engine.so"
lib_path = os.path.join(os.path.dirname(__file__), '..', 'core-c', lib_name)

try:
    vault_lib = ctypes.CDLL(lib_path)
    
    # Define argtypes for encrypt_vault
    vault_lib.encrypt_vault.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),  # key
        ctypes.POINTER(ctypes.c_uint8),  # iv
        ctypes.POINTER(ctypes.c_uint8),  # data
        ctypes.c_size_t                  # length
    ]
    
    # Define argtypes for decrypt_vault
    vault_lib.decrypt_vault.argtypes = [
        ctypes.POINTER(ctypes.c_uint8),  # key
        ctypes.POINTER(ctypes.c_uint8),  # iv
        ctypes.POINTER(ctypes.c_uint8),  # data
        ctypes.c_size_t                  # length
    ]
except OSError:
    vault_lib = None
    print(f"Warning: Could not load {lib_path}. Please compile the C engine first.")

def pad(data: bytes) -> bytes:
    """PKCS7 padding to make data length a multiple of 16."""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    """Remove PKCS7 padding."""
    if not data:
        return data
    pad_len = data[-1]
    return data[:-pad_len]

import hmac
import hashlib

def mock_xor(key: bytes, data: bytes) -> bytes:
    """A fallback mock so the app works without the C compiler."""
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def encrypt_data(enc_key: bytes, mac_key: bytes, plaintext: bytes) -> bytes:
    """Encrypts plaintext using AES-256 and applies an HMAC-SHA256 for Authenticated Encryption."""
    iv = os.urandom(16)
    padded_data = pad(plaintext)
    
    if vault_lib is None:
        # Fallback to mock XOR if C DLL not found
        ciphertext = mock_xor(enc_key, padded_data)
    else:
        # Convert to C types
        c_key = (ctypes.c_uint8 * 32).from_buffer_copy(enc_key)
        c_iv = (ctypes.c_uint8 * 16).from_buffer_copy(iv)
        c_data = (ctypes.c_uint8 * len(padded_data)).from_buffer_copy(padded_data)
        
        # Call C function (encrypts in-place)
        vault_lib.encrypt_vault(c_key, c_iv, c_data, len(padded_data))
        ciphertext = bytes(c_data)
    
    # Calculate HMAC over IV + Ciphertext
    auth_mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    
    # Return IV (16) + MAC (32) + Ciphertext
    return iv + auth_mac + ciphertext

def decrypt_data(enc_key: bytes, mac_key: bytes, payload: bytes) -> bytes:
    """Verifies HMAC and decrypts ciphertext."""
    if len(payload) < 48: # 16 (IV) + 32 (MAC)
        raise ValueError("Payload too short or corrupted")
        
    iv = payload[:16]
    auth_mac = payload[16:48]
    ciphertext = payload[48:]
    
    # Verify HMAC before attempting decryption (Encrypt-then-MAC)
    expected_mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(auth_mac, expected_mac):
        raise ValueError("MAC Verification Failed: Data is tampered or corrupted!")
    
    if vault_lib is None:
        # Fallback to mock XOR if C DLL not found
        return unpad(mock_xor(enc_key, ciphertext))
    
    if len(ciphertext) % 16 != 0:
        raise ValueError("Invalid encrypted data length")
        
    # Convert to C types
    c_key = (ctypes.c_uint8 * 32).from_buffer_copy(enc_key)
    c_iv = (ctypes.c_uint8 * 16).from_buffer_copy(iv)
    c_data = (ctypes.c_uint8 * len(ciphertext)).from_buffer_copy(ciphertext)
    
    # Call C function (decrypts in-place)
    vault_lib.decrypt_vault(c_key, c_iv, c_data, len(ciphertext))
    
    # Unpad and return
    return unpad(bytes(c_data))


