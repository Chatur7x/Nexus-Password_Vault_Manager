import os

def embed_in_bmp(bmp_path: str, vault_data: bytes, out_path: str):
    """Embeds vault bytes into the LSBs of a BMP image."""
    with open(bmp_path, 'rb') as f:
        bmp = bytearray(f.read())
        
    # BMP header is 54 bytes. 
    # Store length of vault data at the beginning (4 bytes = 32 bits)
    vault_len = len(vault_data)
    len_bytes = vault_len.to_bytes(4, 'big')
    
    payload = len_bytes + vault_data
    
    if len(payload) * 8 > (len(bmp) - 54):
        raise ValueError("Image is too small to hide this vault!")
        
    bmp_idx = 54
    for byte in payload:
        for bit_idx in range(7, -1, -1):
            bit = (byte >> bit_idx) & 1
            # Clear LSB and set to our bit
            bmp[bmp_idx] = (bmp[bmp_idx] & 0xFE) | bit
            bmp_idx += 1
            
    with open(out_path, 'wb') as f:
        f.write(bmp)

def extract_from_bmp(bmp_path: str) -> bytes:
    """Extracts vault bytes from the LSBs of a BMP image."""
    with open(bmp_path, 'rb') as f:
        bmp = f.read()
        
    vault_bytes = bytearray()
    bmp_idx = 54
    
    # Read length (4 bytes)
    length = 0
    for _ in range(32):
        bit = bmp[bmp_idx] & 1
        length = (length << 1) | bit
        bmp_idx += 1
        
    if length > 10 * 1024 * 1024: # Sanity check (10MB max)
        raise ValueError("Invalid steganography data found.")
        
    for _ in range(length):
        byte = 0
        for _ in range(8):
            bit = bmp[bmp_idx] & 1
            byte = (byte << 1) | bit
            bmp_idx += 1
        vault_bytes.append(byte)
        
    return bytes(vault_bytes)
