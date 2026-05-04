import os
import functools

# Galois Field (GF(256)) arithmetic
# Precompute exponent and logarithm tables for GF(2^8)
# Irreducible polynomial for AES/GF(2^8) is x^8 + x^4 + x^3 + x + 1 (0x11B)
EXP = [0] * 512
LOG = [0] * 256

x = 1
for i in range(255):
    EXP[i] = x
    LOG[x] = i
    x <<= 1
    if x & 0x100:
        x ^= 0x11B
for i in range(255, 512):
    EXP[i] = EXP[i - 255]

def gf_add(a, b): return a ^ b
def gf_sub(a, b): return a ^ b
def gf_mul(a, b): return 0 if a == 0 or b == 0 else EXP[LOG[a] + LOG[b]]
def gf_div(a, b):
    if b == 0: raise ZeroDivisionError()
    if a == 0: return 0
    return EXP[(LOG[a] + 255 - LOG[b]) % 255]

def eval_poly(poly, x):
    """Evaluates a polynomial in GF(2^8) at x."""
    result = 0
    for coeff in reversed(poly):
        result = gf_mul(result, x) ^ coeff
    return result

def split_secret(secret: bytes, n: int, t: int) -> list[tuple[int, bytes]]:
    """Splits a secret into n shares, requiring t to reconstruct."""
    if t > n: raise ValueError("t must be <= n")
    shares = []
    
    for byte in secret:
        # Polynomial: f(x) = byte + c_1*x + c_2*x^2 + ... + c_{t-1}*x^{t-1}
        poly = [byte] + [os.urandom(1)[0] for _ in range(t - 1)]
        byte_shares = [(i, eval_poly(poly, i)) for i in range(1, n + 1)]
        
        if not shares:
            shares = [[i, bytearray()] for i, _ in byte_shares]
        
        for share_idx in range(n):
            shares[share_idx][1].append(byte_shares[share_idx][1])
            
    return [(idx, bytes(data)) for idx, data in shares]

def recover_secret(shares: list[tuple[int, bytes]]) -> bytes:
    """Recovers the secret from t shares using Lagrange interpolation."""
    if not shares: return b""
    secret = bytearray()
    secret_len = len(shares[0][1])
    
    for i in range(secret_len):
        x_s, y_s = zip(*[(share[0], share[1][i]) for share in shares])
        
        # Interpolate at x=0
        secret_byte = 0
        for j in range(len(x_s)):
            num = 1
            den = 1
            for m in range(len(x_s)):
                if j == m: continue
                num = gf_mul(num, x_s[m])
                den = gf_mul(den, gf_sub(x_s[m], x_s[j]))
            term = gf_mul(y_s[j], gf_div(num, den))
            secret_byte = gf_add(secret_byte, term)
            
        secret.append(secret_byte)
        
    return bytes(secret)
