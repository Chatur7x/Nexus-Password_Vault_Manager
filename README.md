# NEXUS: Zero-Knowledge Password Vault

A military-grade, zero-knowledge password manager built with an advanced cryptographic architecture combining C (for memory-safe encryption execution) and Python (for logic, key derivation, and UI).

## 🖥️ Architecture & Tech Stack

This project was intentionally engineered across three distinct languages to maximize performance, security, and usability:

*   **C (Core Engine)**: Handles bare-metal, memory-safe execution of AES-256-CBC cryptography. Used specifically because C allows direct manipulation and physical wiping of RAM (`SecureZeroMemory`) which garbage-collected languages cannot guarantee.
*   **Python (Middleware & CLI)**: Orchestrates advanced logic, memory-hard key derivation (`scrypt`), HMAC-SHA256 authenticated encryption verification, and serves as the primary system backend.
*   **Java & Python (GUIs)**: The project includes two separate graphical interfaces:
    *   **CustomTkinter (Python)**: A gorgeous, dark-mode "Hacker Terminal" UI natively bound to the backend.
    *   **Swing (Java)**: A lightweight, cross-platform interface operating via isolated subprocess bridging.

---

## 🚀 Advanced Cryptographic Features

### 1. Encrypt-then-MAC (Authenticated Encryption)
Data is encrypted using **AES-256** and subsequently signed using **HMAC-SHA256**. This ensures that even a single byte of tampering to the `.vault` file will cause the decryption to reject the file instantly.

### 2. Scrypt Key Derivation
Master passwords are never used directly. They are stretched through the **Scrypt** memory-hard key derivation function to generate two separate 32-byte keys (Encryption Key and MAC Key), preventing GPU-based brute-force attacks.

### 3. RAM Wiping & Memory Scrambling (ASLR)
To prevent cold-boot and RAM-dump attacks:
* The C-Engine utilizes Windows `SecureZeroMemory` to physically wipe the AES context keys from memory instantly after encryption/decryption.
* The Python Middleware immediately shreds the plaintext passwords into randomized chunks (`ScrambledString`), spreading them across the heap with randomly generated UUIDs and garbage noise. 

### 4. Plausible Deniability (Hidden Vaults)
Supports multiple interleaved vault blocks. Entering a "Decoy Password" decrypts a harmless decoy JSON, making it mathematically impossible for an attacker to prove the existence of the hidden, real vault.

### 5. Honeywords (Intrusion Detection)
For every real password, 5 realistic "Honeywords" are generated and stored alongside it. If a vault is stolen and decrypted, the attacker cannot know which password is real. Using a honeyword on a production system triggers a silent alarm.

### 6. Geofencing & Gutmann Self-Destruct
The application binds itself to the geographic location it was first initialized in (via IP triangulation). If the vault is opened from an unauthorized location, it triggers a `self_destruct()` protocol, overwriting the vault with random noise 7 times before deletion.

### 7. Keystroke Dynamics Biometrics
The GUI tracks the millisecond flight-time between keys when you enter your Master Password. If it detects robotic/macro speeds (<30ms), it instantly trips a bio-metric rejection, locking the system.

### 8. Shamir's Secret Sharing & Steganography
* **Shamir's Split**: Splits the master key into 5 fragments (requiring exactly 3 to recover it).
* **Steganography**: Mathematically embeds the encrypted `.vault` bytes into the Least Significant Bits (LSB) of any `.bmp` image file to hide it in plain sight.

---

## 🛠️ Installation & Usage

**Prerequisites:**
* Python 3.10+
* `pip install customtkinter Pillow`

**Run the Hacker UI:**
```bash
cd gui-python
python ModernVaultApp.py
```

*For maximum security, ensure `gcc` or a C compiler is installed so the backend utilizes the compiled `vault_engine.dll`. If no compiler is found, the system gracefully degrades to a secure XOR stream cipher.*
