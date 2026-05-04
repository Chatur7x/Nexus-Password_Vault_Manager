# Fully Homomorphic Encryption (FHE) Simulation
# This demonstrates computing on encrypted data without decrypting it.
# We will use a highly simplified Paillier-like Partial Homomorphic Encryption
# which allows addition of ciphertexts.

import random

# Large primes (normally 2048-bit, kept small for demo)
p = 499
q = 503
n = p * q
g = n + 1
lmbda = (p - 1) * (q - 1)
mu = pow(lmbda, -1, n)

def fhe_encrypt(m: int) -> int:
    """Encrypt a message m into a homomorphic ciphertext."""
    r = random.randint(1, n-1)
    # c = g^m * r^n mod n^2
    n_sq = n * n
    c = (pow(g, m, n_sq) * pow(r, n, n_sq)) % n_sq
    return c

def fhe_decrypt(c: int) -> int:
    """Decrypt the homomorphic ciphertext."""
    n_sq = n * n
    # L(u) = (u - 1) / n
    def L(u): return (u - 1) // n
    
    u = pow(c, lmbda, n_sq)
    m = (L(u) * mu) % n
    return m

def fhe_add(c1: int, c2: int) -> int:
    """Add two ciphertexts together (math happens in encrypted space)."""
    n_sq = n * n
    # c1 * c2 mod n^2 is equivalent to encrypting (m1 + m2)
    return (c1 * c2) % n_sq

if __name__ == "__main__":
    print("--- Fully Homomorphic Encryption (FHE) Demo ---")
    
    # Imagine a user asking "How many passwords do I have in category A and B?"
    passwords_in_category_a = 15
    passwords_in_category_b = 27
    
    print(f"Plaintext A: {passwords_in_category_a}")
    print(f"Plaintext B: {passwords_in_category_b}")
    
    # Encrypt the data
    c_a = fhe_encrypt(passwords_in_category_a)
    c_b = fhe_encrypt(passwords_in_category_b)
    
    print(f"\nEncrypted Vault Data A: {c_a}")
    print(f"Encrypted Vault Data B: {c_b}")
    
    # The Cloud Server performs math on the encrypted data!
    print("\nCloud server is computing A + B...")
    c_sum = fhe_add(c_a, c_b)
    print(f"Cloud Server Computed Encrypted Sum: {c_sum}")
    
    # The user decrypts the result locally
    result = fhe_decrypt(c_sum)
    print(f"\nUser decrypted the result: {result}")
    
    assert result == passwords_in_category_a + passwords_in_category_b
    print("\nHomomorphic property proven: The server performed math without knowing the plaintext!")
