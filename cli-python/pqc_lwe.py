import os
import random

# A simplified, educational toy implementation of Learning With Errors (LWE)
# This demonstrates the mathematical foundation of Post-Quantum Cryptography (like Kyber)
# WARNING: This is a 1D toy example for education, NOT secure for real-world use!

Q = 3329 # Prime modulus used in Kyber
N = 256  # Dimension
ERROR_LIMIT = 3

def generate_error():
    return random.randint(-ERROR_LIMIT, ERROR_LIMIT)

def keygen():
    """Generates a PQC keypair (s, A, b)."""
    # Secret Key (s)
    s = [random.randint(0, Q-1) for _ in range(N)]
    
    # Public Key (A, b) where b = As + e
    A = [[random.randint(0, Q-1) for _ in range(N)] for _ in range(N)]
    
    b = []
    for i in range(N):
        # Dot product
        dot = sum(A[i][j] * s[j] for j in range(N))
        e = generate_error()
        b.append((dot + e) % Q)
        
    return s, (A, b)

def encrypt(pk, message_bit):
    """Encrypts a single bit using the public key."""
    A, b = pk
    
    # Random ephemeral vector
    r = [random.randint(0, 1) for _ in range(N)]
    
    # u = A^T * r + e1
    u = []
    for i in range(N):
        dot = sum(A[j][i] * r[j] for j in range(N))
        u.append((dot + generate_error()) % Q)
        
    # v = b^T * r + e2 + message * (Q/2)
    v_dot = sum(b[j] * r[j] for j in range(N))
    v = (v_dot + generate_error() + message_bit * (Q // 2)) % Q
    
    return u, v

def decrypt(sk, ciphertext):
    """Decrypts using the secret key."""
    u, v = ciphertext
    
    # Decrypt: v - u^T * s
    dot = sum(u[j] * sk[j] for j in range(N))
    val = (v - dot) % Q
    
    # Is it closer to 0 or Q/2?
    if val > Q//4 and val < 3*Q//4:
        return 1
    return 0

if __name__ == "__main__":
    print("--- Post-Quantum LWE Demo ---")
    sk, pk = keygen()
    
    msg = 1
    print(f"Original Bit: {msg}")
    
    ct = encrypt(pk, msg)
    print("Ciphertext generated (quantum-resistant lattice point).")
    
    dec = decrypt(sk, ct)
    print(f"Decrypted Bit: {dec}")
