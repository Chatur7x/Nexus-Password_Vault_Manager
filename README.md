# NEXUS: Zero-Knowledge Password Vault

A military-grade, zero-knowledge password manager built with an advanced cryptographic architecture combining C (for memory-safe encryption execution) and Python (for logic, key derivation, and UI).

## 🖥️ Architecture & Tech Stack

This project was intentionally engineered across three distinct programming languages to maximize performance, security, and usability:

*   **C (Core Engine)**: Handles bare-metal, memory-safe execution of AES-256-CBC cryptography. Used specifically because C allows direct manipulation and physical wiping of RAM (`SecureZeroMemory` and volatile pointer manipulation), which garbage-collected languages cannot guarantee.
*   **Python (Middleware & CLI)**: Orchestrates advanced logic, memory-hard key derivation (`hashlib.scrypt`), HMAC-SHA256 authenticated encryption verification, and serves as the primary system backend. It securely loads the compiled C `.dll`/`.so` via `ctypes`.
*   **Java & Python (Graphical Interfaces)**: The project includes two separate UI implementations:
    *   **CustomTkinter (Python)**: A gorgeous, dark-mode "Hacker Terminal" UI natively bound to the backend for direct, latency-free memory access.
    *   **Swing (Java)**: A lightweight, cross-platform interface operating via isolated subprocess bridging.

---

## 🚀 Advanced Security Capabilities & Implementation Details

The following features were engineered to resist not only standard cyberattacks but advanced forensic analysis and physical device compromises.

### 1. Encrypt-then-MAC (Authenticated Encryption)
* **Implementation:** The vault payload is first padded (PKCS7) and encrypted via `AES-256-CBC` in the C-Engine. The Python layer then calculates an `HMAC-SHA256` signature using a secondary 256-bit MAC key over the Initialization Vector (IV) and Ciphertext.
* **Security Benefit:** Before any decryption is attempted, the HMAC is verified using a constant-time comparison (`hmac.compare_digest`). This prevents padding oracle attacks and ensures that if a single byte of the `.vault` file is tampered with on disk, the application halts immediately without touching the AES engine.

### 2. GPU-Resistant Key Derivation (Scrypt)
* **Implementation:** The Master Password is never used directly. It is stretched using the memory-hard `scrypt` algorithm (`N=16384, r=8, p=1`). This process generates a 64-byte root key, which is then bifurcated into two separate 32-byte keys: one for AES encryption and one for HMAC verification.
* **Security Benefit:** Scrypt requires significant RAM and CPU cycles to compute, making it highly resistant to ASIC and GPU brute-force cracking attempts by orders of magnitude compared to standard PBKDF2 or SHA-based hashing.

### 3. RAM Wiping & Memory Scrambling (ASLR)
* **Implementation (C):** Upon completing an AES block operation, the C-Engine explicitly calls Windows `SecureZeroMemory()` to physically overwrite the `AES_ctx` struct and round keys with null bytes before returning the pointer.
* **Implementation (Python):** Decrypted JSON strings are immediately shredded by the custom `ScrambledString` class. Individual characters are scattered across the heap and linked together by randomized `uuid4()` pointers, heavily padded with garbage ASCII noise.
* **Security Benefit:** Defeats cold-boot attacks, heap scraping, and advanced memory dump tools (like Mimikatz) that search contiguous RAM blocks for plaintext strings.

### 4. Plausible Deniability (Hidden Vaults)
* **Implementation:** Demonstrated in `plausible_deniability.py`, the architecture supports multiple encrypted payloads interleaved into a single binary blob.
* **Security Benefit:** Entering a "Decoy Password" derives a key that successfully decrypts a harmless JSON payload. To an outside observer (or under duress), it is mathematically impossible to prove that a second "Hidden Password" exists that unlocks the real underlying data.

### 5. Honeywords (Intrusion Detection)
* **Implementation:** When a new password is added via the UI, the backend algorithm generates 5 distinct "Honeywords" (fake passwords) that perfectly match the length and character-class complexity of the real password. The real password is inserted at a randomly seeded index.
* **Security Benefit:** If an attacker successfully compromises the encrypted vault, they will extract a list of 6 seemingly valid passwords per service. If they attempt to use a Honeyword on a monitored production system, an intrusion alarm is triggered.

### 6. Geofencing & Gutmann Self-Destruct
* **Implementation:** Upon initialization, the Python application triangulates its coordinates via an IP-Geolocation API and stores the origin locally. On subsequent executions, it calculates the geographic drift. If the drift exceeds predefined bounds (or if tampered), it triggers the `self_destruct()` protocol.
* **Security Benefit:** The self-destruct mechanism does not just delete the file; it opens the `.vault` and overwrites all bytes with `os.urandom()` across 7 full passes (simulating Gutmann magnetic wiping) before unlinking the inode, rendering forensic data recovery impossible.

### 7. Keystroke Dynamics Biometrics
* **Implementation:** The CustomTkinter login interface binds a `<KeyRelease>` listener to the Master Password input field. It continuously calculates the millisecond "flight-time" between keystrokes.
* **Security Benefit:** If the average flight-time drops below 30ms, the system recognizes the input as physically impossible for a human (flagging it as a robotic macro script or pasted text from a keylogger) and instantly rejects authentication, even if the password is correct.

### 8. Shamir's Secret Sharing & Steganography
* **Implementation (Shamir):** A standalone Galois Field `GF(256)` engine splits the Master Password into 5 hex fragments. Utilizing Lagrange interpolation, any 3 of the 5 shares can reconstruct the key.
* **Implementation (Steganography):** The `stego.py` engine mathematically weaves the ciphertext bytes of the `.vault` file into the Least Significant Bits (LSB) of the RGB channels of a `.bmp` image file. 
* **Security Benefit:** Allows for distributed trust (emergency recovery requiring multiple parties) and "hiding in plain sight" by disguising the vault as an innocuous image file.
