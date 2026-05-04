# Plausible Deniability (Hidden Vault Simulation)
# This script demonstrates how a single file can contain two separate encrypted vaults.
# - The "Decoy Vault" decrypts if Password A is provided.
# - The "Hidden Vault" decrypts if Password B is provided.
# To an outside observer, the file just looks like random bytes, so they cannot prove a Hidden Vault exists.

import os
import json
import hashlib
import hmac

# We'll use a simplified XOR stream cipher for the simulation
def simple_kdf(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

def simple_xor_encrypt(key: bytes, data: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))

def create_plausible_vault(decoy_pass: str, hidden_pass: str):
    print("--- Initializing Dual-Volume Vault ---")
    
    # 1. Generate standard size padded blocks (e.g., 1024 bytes each)
    decoy_data = json.dumps({"SocialMedia": "hunter2"}).ljust(1024, ' ').encode()
    hidden_data = json.dumps({"SwissBank": "millionaire99"}).ljust(1024, ' ').encode()
    
    salt = os.urandom(16)
    
    # 2. Derive distinct keys
    decoy_key = simple_kdf(decoy_pass, salt)
    hidden_key = simple_kdf(hidden_pass, salt)
    
    # 3. Encrypt both blocks
    c_decoy = simple_xor_encrypt(decoy_key, decoy_data)
    c_hidden = simple_xor_encrypt(hidden_key, hidden_data)
    
    # 4. Concatenate into a single file (Decoy at offset 0, Hidden at offset 1024)
    # The whole file looks like 2048 bytes of pure random noise.
    vault_blob = salt + c_decoy + c_hidden
    
    with open("dual_volume.vault", "wb") as f:
        f.write(vault_blob)
    print("Vault created successfully! (Looks like 2064 bytes of random noise)\n")

def open_vault(password: str):
    if not os.path.exists("dual_volume.vault"):
        print("Vault not found.")
        return
        
    with open("dual_volume.vault", "rb") as f:
        data = f.read()
        
    salt = data[:16]
    c_decoy = data[16:1040]
    c_hidden = data[1040:2064]
    
    key = simple_kdf(password, salt)
    
    # Try Decoy
    pt_decoy = simple_xor_encrypt(key, c_decoy)
    try:
        j = json.loads(pt_decoy.decode().strip())
        print(f"✅ DECOY VAULT UNLOCKED with '{password}':")
        print(j)
        return
    except:
        pass
        
    # Try Hidden
    pt_hidden = simple_xor_encrypt(key, c_hidden)
    try:
        j = json.loads(pt_hidden.decode().strip())
        print(f"🚨 HIDDEN VAULT UNLOCKED with '{password}':")
        print(j)
        return
    except:
        pass
        
    print(f"❌ FAILED. '{password}' did not unlock any volumes.")

if __name__ == "__main__":
    decoy = "fake_password_123"
    hidden = "super_secret_ghost"
    
    create_plausible_vault(decoy, hidden)
    
    print("Scenario 1: Attacker forces you to give a password.")
    print(f"You give them the decoy: '{decoy}'")
    open_vault(decoy)
    
    print("\nScenario 2: You are alone and need your real bank password.")
    print(f"You type the hidden password: '{hidden}'")
    open_vault(hidden)
    
    print("\nScenario 3: Attacker tries to guess.")
    open_vault("wrong_guess")
    
    # Cleanup
    if os.path.exists("dual_volume.vault"):
        os.remove("dual_volume.vault")
