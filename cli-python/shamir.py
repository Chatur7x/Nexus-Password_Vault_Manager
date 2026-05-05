"""
NEXUS Shamir's Secret Sharing — Correct GF(256) Implementation

Fixed GF(2^8) tables using generator g=3 (primitive root) which produces
a correct, non-overlapping EXP/LOG table where LOG[1]=0 is preserved.

Tested: all C(5,3)=10 share combinations reconstruct correctly.
"""

import os
import itertools

# ──────────────────────────────────────────────────────────────────────────────
# GF(2^8) Arithmetic using generator g=3
# Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B)
# ──────────────────────────────────────────────────────────────────────────────

_EXP = [1] * 256   # Anti-log table (generator powers)
_LOG = [0] * 256   # Logarithm table

_x = 1
for _i in range(1, 256):
    # Multiply _x by g=3 in GF(256)
    _x = (_x << 1) ^ (_x >> 7) * 0x1B  # multiply by 2
    _x ^= _EXP[_i - 1]                  # add previous (multiply by 3 = 2+1)
    _x &= 0xFF
    _EXP[_i % 255] = _x
    _LOG[_x] = _i % 255

_LOG[1] = 0  # LOG[1] must always be 0 (since g^0 = 1)


def gf_mul(a: int, b: int) -> int:
    """Multiply two GF(256) elements."""
    if a == 0 or b == 0:
        return 0
    return _EXP[(_LOG[a] + _LOG[b]) % 255]


def gf_add(a: int, b: int) -> int:
    """Add two GF(256) elements (XOR)."""
    return a ^ b


def gf_inv(a: int) -> int:
    """Multiplicative inverse in GF(256)."""
    if a == 0:
        raise ZeroDivisionError("No inverse of 0 in GF(256)")
    return _EXP[(255 - _LOG[a]) % 255]


def gf_div(a: int, b: int) -> int:
    """Divide a by b in GF(256)."""
    if b == 0:
        raise ZeroDivisionError("GF division by zero")
    if a == 0:
        return 0
    return gf_mul(a, gf_inv(b))


def eval_poly(coefficients: list[int], x: int) -> int:
    """
    Evaluate polynomial f(x) = c0 + c1*x + c2*x^2 + ... at point x.
    Uses Horner's method: f(x) = c0 + x*(c1 + x*(c2 + ...))
    coefficients[0] is the constant term (the secret byte).
    """
    result = 0
    # Horner: iterate coefficients in reverse (highest degree first)
    for coeff in reversed(coefficients):
        result = gf_add(gf_mul(result, x), coeff)
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Shamir's Secret Sharing
# ──────────────────────────────────────────────────────────────────────────────

def split_secret(secret: bytes, n: int, t: int) -> list[tuple[int, bytes]]:
    """
    Split a secret into n shares, requiring exactly t shares to reconstruct.
    
    Args:
        secret: The secret bytes to split
        n: Total number of shares to generate
        t: Minimum shares required to reconstruct (threshold)
    
    Returns:
        List of (share_index, share_bytes) tuples. Indices are 1..n.
    """
    if t > n:
        raise ValueError(f"threshold t={t} must be <= n={n}")
    if t < 2:
        raise ValueError("threshold t must be >= 2 for security")
    if n > 255:
        raise ValueError("n must be <= 255 (GF(256) field size)")
    if not secret:
        raise ValueError("secret cannot be empty")

    shares = [bytearray() for _ in range(n)]

    for byte_val in secret:
        # Polynomial coefficients: f(x) = byte_val + c1*x + c2*x^2 + ... + c(t-1)*x^(t-1)
        # coefficients[0] = secret byte (constant term), rest are cryptographically random
        coefficients = [byte_val] + [os.urandom(1)[0] for _ in range(t - 1)]

        # Evaluate at share indices 1..n (we never evaluate at x=0, that IS the secret)
        for i in range(n):
            x_val = i + 1
            y_val = eval_poly(coefficients, x_val)
            shares[i].append(y_val)

    return [(i + 1, bytes(share)) for i, share in enumerate(shares)]


def recover_secret(shares: list[tuple[int, bytes]]) -> bytes:
    """
    Recover the original secret from any t shares using Lagrange interpolation.
    Evaluates the interpolating polynomial at x=0 (the secret).
    
    Args:
        shares: List of (share_index, share_bytes) tuples
    
    Returns:
        Reconstructed secret bytes
    """
    if not shares:
        return b""

    share_len = len(shares[0][1])
    for idx, data in shares:
        if len(data) != share_len:
            raise ValueError("All shares must have equal byte length")

    secret = bytearray()

    for byte_pos in range(share_len):
        # Collect (x, y) evaluation points for this byte position
        points = [(idx, data[byte_pos]) for idx, data in shares]

        # Lagrange interpolation at x=0 over GF(256)
        # f(0) = sum_j [ y_j * L_j(0) ]
        # L_j(0) = product_{m != j} [ (0 - x_m) / (x_j - x_m) ]
        # In GF(256): 0 - a = a, a - b = a XOR b
        secret_byte = 0
        for j, (x_j, y_j) in enumerate(points):
            lagrange = 1
            for m, (x_m, _) in enumerate(points):
                if m == j:
                    continue
                # numerator factor: (0 - x_m) = x_m in GF (subtraction = XOR)
                # denominator factor: (x_j - x_m) = x_j XOR x_m
                numerator = x_m
                denominator = gf_add(x_j, x_m)
                lagrange = gf_mul(lagrange, gf_div(numerator, denominator))

            secret_byte = gf_add(secret_byte, gf_mul(y_j, lagrange))

        secret.append(secret_byte)

    return bytes(secret)


def verify_shares(original_secret: bytes, shares: list[tuple[int, bytes]], t: int) -> bool:
    """
    Verify that any combination of t shares correctly reconstructs the secret.
    Used for testing / post-generation validation.
    """
    for combo in itertools.combinations(shares, t):
        recovered = recover_secret(list(combo))
        if recovered != original_secret:
            return False
    return True


# ──────────────────────────────────────────────────────────────────────────────
# Self-Test
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 50)
    print("  NEXUS Shamir GF(256) — Full Verification")
    print("=" * 50)

    test_secrets = [
        b"NEXUS_MASTER_KEY_32_BYTES_LONG!!",
        b"short",
        os.urandom(64),
        b"\x00\xff\xab\xcd" * 8
    ]

    all_pass = True
    for i, secret in enumerate(test_secrets):
        n, t = 5, 3
        shares = split_secret(secret, n, t)

        # Test all combinations of t shares
        for combo in itertools.combinations(shares, t):
            recovered = recover_secret(list(combo))
            if recovered != secret:
                print(f"FAIL test {i}: combo {[s[0] for s in combo]}")
                all_pass = False

        # Verify t-1 shares do NOT reconstruct
        partial = recover_secret(list(shares[:t-1]))
        if partial == secret:
            print(f"FAIL test {i}: threshold not enforced (t-1 shares reconstructed secret)")
            all_pass = False

        print(f"PASS test {i}: {len(secret)} bytes, all C({n},{t})={len(list(itertools.combinations(range(n),t)))} combos verified")

    print()
    if all_pass:
        print("ALL TESTS PASSED [OK]")
    else:
        print("SOME TESTS FAILED [!!]")
