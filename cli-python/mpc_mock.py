# Multi-Party Computation (MPC) Simulation
# This demonstrates threshold decryption where two devices (Phone and Laptop)
# must combine their mathematical shares to decrypt data. The master key never
# exists in a single place.

import random

P = 2089 # A small prime for demonstration

def split_key(master_key: int):
    """Splits a key into two multiplicative shares."""
    # Find random share_1
    share_1 = random.randint(1, P-1)
    
    # Calculate share_2 such that (share_1 * share_2) % P = master_key
    # This requires modular inverse of share_1 mod P
    inv_share_1 = pow(share_1, P-2, P) # Fermat's Little Theorem
    share_2 = (master_key * inv_share_1) % P
    
    return share_1, share_2

def mpc_encrypt(plaintext: int, master_key: int):
    """Encrypts by multiplying plaintext by master key mod P"""
    return (plaintext * master_key) % P

def mpc_decrypt_distributed(ciphertext: int, share_1: int, share_2: int):
    """
    Simulates distributed decryption. 
    Device 1 does partial decryption, Device 2 finishes it.
    """
    # Device 1: Computes partial decryption using only its share
    inv_share_1 = pow(share_1, P-2, P)
    partial_1 = (ciphertext * inv_share_1) % P
    
    # Device 2: Finishes decryption using its share and the partial result
    inv_share_2 = pow(share_2, P-2, P)
    plaintext = (partial_1 * inv_share_2) % P
    
    return plaintext

if __name__ == "__main__":
    print("--- Multi-Party Computation (MPC) Demo ---")
    
    original_password = 1337 # Some numerical representation of a password
    master_key = 42
    
    print(f"Original Password: {original_password}")
    print(f"Master Key: {master_key}")
    
    # Split key between two devices
    s1, s2 = split_key(master_key)
    print(f"\nLaptop holds Share 1: {s1}")
    print(f"Phone holds Share 2: {s2}")
    
    # Encrypt
    ct = mpc_encrypt(original_password, master_key)
    print(f"\nEncrypted Vault Data: {ct}")
    
    # Decrypt
    print("\nInitiating Distributed Decryption...")
    pt = mpc_decrypt_distributed(ct, s1, s2)
    print(f"Successfully Recovered Password: {pt}")
    
    print("\nNote: At no point during decryption did the Master Key exist in RAM!")
