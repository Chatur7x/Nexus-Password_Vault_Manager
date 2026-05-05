# NEXUS: Zero-Knowledge Password Vault

A military-grade, zero-knowledge password manager engineered to defeat remote attackers, physical forensics, and server breaches — built across C, Python, Java, and a cross-platform Web/Android frontend.

---

## 🖥️ Architecture & Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Core Crypto Engine** | C | Bare-metal AES-256-GCM, SecureZeroMemory RAM wiping |
| **Middleware & CLI** | Python | Argon2id KDF, HMAC verification, all security modules |
| **ZK Sync Server** | Python (FastAPI) | Zero-knowledge encrypted blob storage, SCIM, PAM |
| **Web App** | Vite + Vanilla JS | Cross-platform PWA with WebCrypto API |
| **Android App** | Capacitor | Native Android wrapper for the web app |
| **Browser Extension** | Manifest V3 | AutoFill, phishing detection, domain matching |
| **Desktop GUIs** | CustomTkinter / Java Swing | Native desktop interfaces |

---

## 🔐 Cryptographic Stack

| Layer | Algorithm | Standard |
|---|---|---|
| Symmetric Encryption | AES-256-GCM | NIST SP 800-38D |
| Key Derivation | Argon2id | PHC Winner, OWASP Recommended |
| Key Exchange | X25519 (Curve25519) | RFC 7748 |
| Digital Signatures | Ed25519 | RFC 8032 |
| Hashing | SHA-256 / BLAKE3 | FIPS 180-4 |
| Post-Quantum | ML-KEM (Kyber) | NIST PQC (Roadmap) |
| Transport | TLS 1.3 only | RFC 8446 |

---

## 🚀 Complete Feature List

### Core Vault
- AES-256-GCM authenticated encryption
- Argon2id memory-hard key derivation (replaces scrypt)
- Encrypt-then-MAC (HMAC-SHA256) file integrity
- Client-side only execution (WebCrypto API)
- Integrated TOTP 2FA authenticator
- Secure 24-character password generator
- HaveIBeenPwned k-Anonymity breach monitoring

### Record Types
- Passwords with Honeyword intrusion detection
- Structured Secure Notes
- SSH Key storage
- API Key / Developer Secret management
- IoT / Smart Home device credentials
- Connected Vehicle credential store

### Physical Security
- Bluetooth Proximity Auto-Lock (paired phone/watch)
- USB Physical Key (removable drive as auth factor)
- Duress PIN (decoy vault + silent alarm to emergency contact)
- Thermal Attack Resistance (keyboard heat contamination)
- Anti-Screenshot Protection (Android FLAG_SECURE)
- Clipboard Isolation (sandboxed copy, no OS clipboard)

### Network Security
- DNS-over-HTTPS for all vault traffic
- Certificate Transparency log monitoring
- SSID Spoofing / Evil Twin detection (replaces geofencing)
- Network Traffic Obfuscation (CDN-disguised sync)
- Trusted Network Registry (SSID + BSSID verification)

### Behavioral Authentication
- Continuous Session Verification (behavioral drift detection)
- Mouse Dynamics Biometrics (velocity/acceleration profiling)
- Passive Liveness Detection (anti-photo/mask for Face ID)
- Ephemeral Session Tokens (15-minute TTL, auto-lock)

### Deception & Intrusion Detection
- Plausible Deniability (hidden/decoy vaults)
- Honeywords (5 fake passwords per entry)
- Access Anomaly Detection (z-score statistical alerts)

### Recovery & Resilience
- Distributed Cloud Backup (3-fragment Shamir across providers)
- BIP39 Mnemonic Recovery Kit (24-word printable seed)
- 90-Day Version-Controlled Vault History (rollback)
- Merkle Tree Backup Integrity Verification
- Travel Mode (strip sensitive entries at borders)

### Cryptographic Audit Trail
- Tamper-Evident Hash Chain (mini-blockchain)
- Signed Access Receipts (HMAC-SHA256 timestamped)
- Anomaly Detection on access patterns

### Secure Sharing
- Time-Limited Credential Sharing
- One-Time-Use Share Links (auto-burn after access)
- Encrypted share payloads (X25519 key exchange)

### Enterprise & Compliance
- SIEM Export (CEF / JSON / Syslog for Splunk/Elastic/Datadog)
- SCIM 2.0 Provisioning (Okta, Azure AD, Google Workspace)
- SOC 2 / ISO 27001 One-Click Compliance Report
- Privileged Access Management (PAM checkout/approval)

### Transparency & Trust
- Reproducible Build Verification (SHA-256 manifest)
- Public Security Audit Dashboard
- In-App Cryptographic Proof Verifier (key ownership, sync integrity)

### Cross-Platform
- Desktop (Python GUI, Java Swing, Web Browser)
- Android (Capacitor native APK)
- Web App (Vite PWA, works on any device)
- Browser Extension (Chrome/Edge/Firefox AutoFill + Phishing Detection)

---

## 🛠️ Installation & Usage

### Prerequisites
```bash
pip install argon2-cffi customtkinter Pillow
```

### Running the CLI
```bash
cd cli-python
python manager.py list
python manager.py add --title Gmail --user me@gmail.com --password "MySecurePass!"
python manager.py get Gmail
python manager.py health
```

### Advanced CLI Commands
```bash
python manager.py travel-mode            # Strip sensitive entries
python manager.py recovery-kit           # Generate BIP39 seed words
python manager.py history                # List vault snapshots
python manager.py restore 20260505_1200  # Rollback to snapshot
python manager.py audit-verify           # Verify audit chain integrity
python manager.py audit-log              # View recent access events
python manager.py network-check          # SSID spoofing detection
python manager.py network-scan           # Discover local devices
python manager.py ct-scan                # Certificate Transparency check
python manager.py soc2-report            # Generate compliance report
python manager.py build-manifest         # Reproducible build hash
python manager.py verify-build           # Verify source integrity
python manager.py bt-pair AA:BB:CC:DD    # Pair Bluetooth device
python manager.py duress-setup --pin 9999 --webhook https://hooks.slack.com/...
python manager.py iot-add --name Router --type router --ip 192.168.1.1
```

### Running the Web App
```bash
cd nexus-web
npm install
npm run dev
```

### Running the Sync Server
```bash
cd sync-server
pip install fastapi uvicorn
python main.py
```

---

## 📁 Project Structure

```
PASS-VAULT-MANAGER/
├── core-c/                  # C Engine — AES-256, SecureZeroMemory
├── cli-python/              # Python Backend — All security modules
│   ├── manager.py           # Main CLI entry point (25+ commands)
│   ├── auth.py              # Argon2id key derivation
│   ├── c_bridge.py          # C DLL bridge via ctypes
│   ├── behavioral_auth.py   # Continuous session verification
│   ├── physical_security.py # BT lock, USB key, duress PIN, thermal
│   ├── network_security.py  # DoH, CT monitoring, SSID spoofing
│   ├── recovery.py          # Distributed backup, BIP39, version history
│   ├── audit_trail.py       # Hash chain, signed receipts, anomaly detection
│   ├── enterprise.py        # SIEM, SCIM, SOC2, PAM
│   ├── iot_integration.py   # Smart home, network discovery, vehicles
│   ├── transparency.py      # Reproducible builds, audit dashboard, proofs
│   ├── shamir.py            # Shamir's Secret Sharing (GF256)
│   ├── stego.py             # Steganography (research demo)
│   ├── fhe_mock.py          # FHE simulation (research demo)
│   ├── mpc_mock.py          # MPC simulation (research demo)
│   └── pqc_lwe.py           # Post-quantum LWE (research demo)
├── sync-server/             # FastAPI Zero-Knowledge Sync Server
│   └── main.py              # SCIM, PAM, sharing, transparency APIs
├── nexus-web/               # Vite + Capacitor Web/Android App
├── browser-extension/       # Manifest V3 Chrome/Edge Extension
├── gui-python/              # CustomTkinter Desktop GUI
├── gui-java/                # Java Swing Desktop GUI
└── data/                    # Encrypted vault storage
```

---

## ⚠️ Threat Model

| Attack Vector | Status | Defense |
|---|---|---|
| Remote vault file theft | ✅ Defeated | AES-256-GCM + ZK server |
| Server breach | ✅ Defeated | Zero-knowledge — server holds no keys |
| Physical device theft | ⚠️ Largely | Argon2id + Secure Enclave (roadmap) |
| Memory scraping | ⚠️ Partially | SecureZeroMemory + RAM scrambling |
| Phishing | ✅ Defeated | Browser extension domain-match blocking |
| Evil Twin WiFi | ✅ Defeated | SSID + BSSID fingerprint verification |
| Insider threat | ✅ Defeated | Encrypted metadata + ZK architecture |
| Coercion / duress | ✅ Defeated | Duress PIN + decoy vault + silent alarm |
| Quantum computer | 🔄 Roadmap | ML-KEM hybrid mode |
