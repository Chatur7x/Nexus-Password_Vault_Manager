# NEXUS: Zero-Knowledge Password Vault

A military-grade, zero-knowledge password manager built with an advanced cryptographic architecture combining C (for memory-safe encryption execution) and Python (for logic, key derivation, and UI).

---

## 🖥️ Architecture & Tech Stack

This project was intentionally engineered across three distinct programming languages to maximize performance, security, and usability:

*   **C (Core Engine)**: Handles bare-metal, memory-safe execution of AES-256-CBC cryptography. Used specifically because C allows direct manipulation and physical wiping of RAM (`SecureZeroMemory` and volatile pointer manipulation), which garbage-collected languages cannot guarantee.
*   **Python (Middleware & CLI)**: Orchestrates advanced logic, memory-hard key derivation (`hashlib.scrypt`), HMAC-SHA256 authenticated encryption verification, and serves as the primary system backend. It securely loads the compiled C `.dll`/`.so` via `ctypes`.
*   **Java & Python (Graphical Interfaces)**: The project includes two separate UI implementations:
    *   **CustomTkinter (Python)**: A gorgeous, dark-mode "Hacker Terminal" UI natively bound to the backend for direct, latency-free memory access.
    *   **Swing (Java)**: A lightweight, cross-platform interface operating via isolated subprocess bridging.

---

## 🚀 Advanced Security Capabilities

The following features were engineered to resist not only standard cyberattacks but advanced forensic analysis and physical device compromises.

### 1. Encrypt-then-MAC (Authenticated Encryption)
* **Implementation:** The vault payload is first padded (PKCS7) and encrypted via `AES-256-CBC` in the C-Engine. The Python layer then calculates an `HMAC-SHA256` signature using a secondary 256-bit MAC key over the Initialization Vector (IV) and Ciphertext.
* **Security Benefit:** Before any decryption is attempted, the HMAC is verified using a constant-time comparison. This prevents padding oracle attacks and ensures that if a single byte of the `.vault` file is tampered with on disk, the application halts immediately.

### 2. GPU-Resistant Key Derivation (Scrypt)
* **Implementation:** The Master Password is never used directly. It is stretched using the memory-hard `scrypt` algorithm (`N=16384, r=8, p=1`). This generates a 64-byte root key, which is then bifurcated into two separate 32-byte keys.
* **Security Benefit:** Scrypt requires significant RAM and CPU cycles to compute, making it highly resistant to ASIC and GPU brute-force cracking attempts by orders of magnitude.

### 3. RAM Wiping & Memory Scrambling (ASLR)
* **Implementation (C):** Upon completing an AES block operation, the C-Engine explicitly calls Windows `SecureZeroMemory()` to physically overwrite the `AES_ctx` struct and round keys with null bytes.
* **Implementation (Python):** Decrypted strings are immediately shredded by a custom `ScrambledString` class. Individual characters are scattered across the heap and linked together by randomized `uuid4()` pointers, padded with ASCII noise.
* **Security Benefit:** Defeats cold-boot attacks, heap scraping, and advanced memory dump tools (like Mimikatz).

### 4. Plausible Deniability (Hidden Vaults)
* **Implementation:** The architecture supports multiple encrypted payloads interleaved into a single binary blob.
* **Security Benefit:** Entering a "Decoy Password" decrypts a harmless payload. To an outside observer (or under duress), it is mathematically impossible to prove that a second "Hidden Password" exists.

### 5. Honeywords (Intrusion Detection)
* **Implementation:** When a new password is added, the algorithm generates 5 distinct "Honeywords" (fake passwords) that perfectly match the character-class complexity of the real password. The real password is inserted at a randomly seeded index.
* **Security Benefit:** If an attacker extracts a list of passwords, they cannot know which is real. Attempting to use a Honeyword on a production system triggers an intrusion alarm.

### 6. Geofencing & Gutmann Self-Destruct
* **Implementation:** The application triangulates its coordinates via an IP-Geolocation API. If geographic drift exceeds predefined bounds, it triggers the `self_destruct()` protocol.
* **Security Benefit:** Overwrites the vault with `os.urandom()` across 7 full passes (simulating Gutmann magnetic wiping) before unlinking the inode, rendering forensic data recovery impossible.

### 7. Keystroke Dynamics Biometrics
* **Implementation:** The login interface continuously calculates the millisecond "flight-time" between keystrokes.
* **Security Benefit:** If the average flight-time drops below 30ms, the system recognizes the input as physically impossible for a human (flagging it as a robotic macro script) and instantly rejects authentication.

### 8. Shamir's Secret Sharing & Steganography
* **Implementation (Shamir):** A Galois Field `GF(256)` engine splits the Master Password into 5 hex fragments. Utilizing Lagrange interpolation, any 3 of the 5 shares can reconstruct the key.
* **Implementation (Steganography):** Mathematically weaves the ciphertext bytes of the `.vault` file into the Least Significant Bits (LSB) of the RGB channels of a `.bmp` image file. 

---

## 🛠️ Installation & Usage Guide

Follow these steps to initialize and run the NEXUS Vault on your local machine.

### Prerequisites
1. Ensure **Python 3.10+** is installed on your system.
2. Install the required UI and cryptography rendering dependencies:
   ```bash
   pip install customtkinter Pillow
   ```

### Running the Application
To launch the primary Dark-Mode "Hacker Terminal" UI:

1. Open your terminal or command prompt.
2. Navigate to the `gui-python` directory:
   ```bash
   cd PASS-VAULT-MANAGER/gui-python
   ```
3. Run the application:
   ```bash
   pythonw ModernVaultApp.py
   ```
   *(Note: Using `pythonw` instead of `python` runs the application seamlessly without keeping a background terminal window open).*

### First-Time Setup
*   When you open the application for the first time, simply type your desired **Master Password** into the prompt. 
*   The system will automatically generate a secure Salt and initialize a brand new AES-256 encrypted `.vault` file bound to that specific password. 

### Advanced Usage Notes
*   **Hardware Acceleration:** For maximum security and speed, if you are running this on a Linux system or have `gcc` (MinGW) installed on Windows, navigate to `core-c` and run `compile.bat` or `make` to compile the `vault_engine.dll`. The Python system will automatically detect the C-library and use it. If no compiler is present, the app gracefully degrades to a secure Python stream cipher.
