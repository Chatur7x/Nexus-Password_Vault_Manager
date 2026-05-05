"""
NEXUS Network Security Layer (9.3)

Implements:
- DNS-over-HTTPS (DoH) for all vault network requests
- Certificate Transparency (CT) Log Monitoring
- SSID Spoofing Detection (Evil Twin Attack prevention)
- Network Traffic Obfuscation (disguise sync as CDN HTTPS)
"""

import json
import hashlib
import os
import time
import urllib.request
import ssl
import base64
import struct
import subprocess
import platform
from datetime import datetime, timezone

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')


class DNSOverHTTPS:
    """
    Routes all NEXUS DNS lookups through encrypted DNS-over-HTTPS.
    Prevents ISP-level surveillance from seeing which domains NEXUS resolves.
    Supports Cloudflare (1.1.1.1) and Google (8.8.8.8) DoH endpoints.
    """

    DOH_PROVIDERS = {
        "cloudflare": "https://cloudflare-dns.com/dns-query",
        "google": "https://dns.google/resolve",
    }

    def __init__(self, provider: str = "cloudflare"):
        self.provider = provider
        self.endpoint = self.DOH_PROVIDERS.get(provider, self.DOH_PROVIDERS["cloudflare"])

    def resolve(self, domain: str, record_type: str = "A") -> list[str]:
        """
        Resolve a domain name via DNS-over-HTTPS.
        Returns a list of IP addresses or records.
        """
        try:
            url = f"{self.endpoint}?name={domain}&type={record_type}"
            req = urllib.request.Request(url, headers={
                'Accept': 'application/dns-json',
                'User-Agent': 'NEXUS-Vault/2.0'
            })

            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=5, context=ctx) as response:
                data = json.loads(response.read().decode('utf-8'))

            answers = data.get("Answer", [])
            return [a["data"] for a in answers]

        except Exception as e:
            # Fall back to system DNS silently
            return []

    def resolve_sync_server(self, sync_domain: str) -> str:
        """Resolve the ZK sync server address via DoH."""
        ips = self.resolve(sync_domain)
        if ips:
            return ips[0]
        return sync_domain  # Fallback


class CertificateTransparencyMonitor:
    """
    Monitors Certificate Transparency logs for new SSL certificates
    issued for domains stored in the user's vault.

    If an unexpected certificate appears (e.g., a rogue CA issues a cert
    for paypal.com), NEXUS alerts immediately — an early warning for
    man-in-the-middle infrastructure being deployed.
    """

    CT_API = "https://crt.sh/?q={domain}&output=json"

    def __init__(self):
        self.known_certs = {}  # domain -> set of cert fingerprints
        self.alerts = []

    def check_domain(self, domain: str) -> list[dict]:
        """
        Query Certificate Transparency logs for a domain.
        Returns list of new/unknown certificates.
        """
        new_certs = []
        try:
            url = self.CT_API.format(domain=domain)
            req = urllib.request.Request(url, headers={
                'User-Agent': 'NEXUS-CT-Monitor/1.0'
            })
            with urllib.request.urlopen(req, timeout=10) as response:
                certs = json.loads(response.read().decode('utf-8'))

            known = self.known_certs.get(domain, set())

            for cert in certs[:50]:  # Check most recent 50
                cert_id = str(cert.get("id", ""))
                issuer = cert.get("issuer_name", "unknown")
                not_before = cert.get("not_before", "")
                serial = cert.get("serial_number", "")

                if cert_id not in known:
                    new_certs.append({
                        "domain": domain,
                        "cert_id": cert_id,
                        "issuer": issuer,
                        "issued_date": not_before,
                        "serial": serial
                    })
                    known.add(cert_id)

            self.known_certs[domain] = known

        except Exception:
            pass

        if new_certs:
            self.alerts.extend(new_certs)

        return new_certs

    def scan_vault_domains(self, vault_data: dict) -> list[dict]:
        """Scan all domains stored in the vault for suspicious certificates."""
        all_alerts = []
        for title, entry in vault_data.items():
            url = entry.get("url", "")
            if url:
                try:
                    from urllib.parse import urlparse
                    domain = urlparse(url).hostname or url
                except Exception:
                    domain = url
                alerts = self.check_domain(domain)
                all_alerts.extend(alerts)
        return all_alerts


class SSIDSpoofingDetector:
    """
    Detects Evil Twin attacks by verifying not just the SSID name
    but also the router's MAC address (BSSID) and signal characteristics.

    If you connect to "HomeWiFi" but the MAC address is different from
    the last time, this is likely an evil twin / rogue access point.
    """

    def __init__(self):
        self.trusted_networks_path = os.path.join(DATA_DIR, 'trusted_networks.json')
        self.trusted_networks = self._load_trusted()

    def _load_trusted(self) -> dict:
        if os.path.exists(self.trusted_networks_path):
            with open(self.trusted_networks_path, 'r') as f:
                return json.load(f)
        return {}

    def _save_trusted(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(self.trusted_networks_path, 'w') as f:
            json.dump(self.trusted_networks, f, indent=2)

    def get_current_network(self) -> dict:
        """
        Get the current WiFi SSID and BSSID (router MAC).
        Windows: netsh wlan show interfaces
        macOS: /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I
        Linux: iwgetid / nmcli
        """
        network_info = {"ssid": None, "bssid": None}

        try:
            if platform.system() == "Windows":
                output = subprocess.check_output(
                    ['netsh', 'wlan', 'show', 'interfaces'],
                    text=True, timeout=5
                )
                for line in output.splitlines():
                    line = line.strip()
                    if line.startswith("SSID") and "BSSID" not in line:
                        network_info["ssid"] = line.split(":", 1)[1].strip()
                    elif line.startswith("BSSID"):
                        network_info["bssid"] = line.split(":", 1)[1].strip()

            elif platform.system() == "Darwin":
                output = subprocess.check_output(
                    ['/System/Library/PrivateFrameworks/Apple80211.framework/'
                     'Versions/Current/Resources/airport', '-I'],
                    text=True, timeout=5
                )
                for line in output.splitlines():
                    line = line.strip()
                    if line.startswith("SSID"):
                        network_info["ssid"] = line.split(":", 1)[1].strip()
                    elif line.startswith("BSSID"):
                        network_info["bssid"] = line.split(":", 1)[1].strip()

            elif platform.system() == "Linux":
                ssid = subprocess.check_output(
                    ['iwgetid', '-r'], text=True, timeout=5
                ).strip()
                bssid = subprocess.check_output(
                    ['iwgetid', '-rap'], text=True, timeout=5
                ).strip()
                network_info["ssid"] = ssid
                network_info["bssid"] = bssid

        except Exception:
            pass

        return network_info

    def trust_current_network(self):
        """Mark the current network as trusted."""
        net = self.get_current_network()
        if net["ssid"]:
            self.trusted_networks[net["ssid"]] = {
                "bssid": net["bssid"],
                "trusted_at": datetime.now(timezone.utc).isoformat()
            }
            self._save_trusted()
            print(f"✅ Network '{net['ssid']}' (BSSID: {net['bssid']}) marked as trusted.")

    def verify_network(self) -> dict:
        """
        Verify the current network against trusted list.
        Returns verification result with risk level.
        """
        net = self.get_current_network()
        result = {
            "ssid": net["ssid"],
            "bssid": net["bssid"],
            "is_trusted": False,
            "risk": "unknown",
            "reason": ""
        }

        if not net["ssid"]:
            result["risk"] = "no_wifi"
            result["reason"] = "No WiFi connection detected (wired or disconnected)."
            result["is_trusted"] = True  # Wired connections are fine
            return result

        trusted = self.trusted_networks.get(net["ssid"])

        if trusted is None:
            result["risk"] = "unknown_network"
            result["reason"] = f"Network '{net['ssid']}' has never been seen before."
            return result

        if trusted["bssid"] and net["bssid"]:
            if trusted["bssid"].lower() == net["bssid"].lower():
                result["is_trusted"] = True
                result["risk"] = "safe"
                result["reason"] = "SSID and BSSID match trusted profile."
            else:
                result["risk"] = "evil_twin_suspected"
                result["reason"] = (
                    f"⚠️ SSID matches '{net['ssid']}' but BSSID changed! "
                    f"Expected {trusted['bssid']}, got {net['bssid']}. "
                    f"Possible Evil Twin / Rogue Access Point attack."
                )
        else:
            result["is_trusted"] = True
            result["risk"] = "partial_match"
            result["reason"] = "SSID matches but BSSID unavailable for verification."

        return result


class TrafficObfuscator:
    """
    Disguises NEXUS vault sync traffic as standard HTTPS CDN requests.
    Useful for users in environments where specific app traffic is
    monitored or blocked (enterprise firewalls, authoritarian regimes).
    """

    # Simulate traffic as if it were fetching static assets from a CDN
    CDN_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0",
        "Accept": "text/html,application/xhtml+xml,*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Cache-Control": "no-cache",
    }

    @staticmethod
    def wrap_payload(encrypted_blob: str) -> dict:
        """
        Wrap an encrypted vault payload to look like a CDN asset response.
        The encrypted data is base64-encoded and placed in a JSON structure
        that mimics a static asset API response.
        """
        return {
            "version": "1.0",
            "asset_type": "application/octet-stream",
            "cache_key": hashlib.md5(encrypted_blob[:32].encode()).hexdigest(),
            "data": encrypted_blob,
            "etag": hashlib.sha256(encrypted_blob.encode()).hexdigest()[:16],
            "timestamp": int(time.time()),
            "cdn_node": "edge-us-west-2"
        }

    @staticmethod
    def unwrap_payload(cdn_response: dict) -> str:
        """Extract the encrypted vault blob from the CDN-wrapped response."""
        return cdn_response.get("data", "")

    @staticmethod
    def add_timing_jitter(min_ms: int = 50, max_ms: int = 300):
        """
        Add random timing jitter between requests to prevent traffic analysis.
        Makes request patterns indistinguishable from normal browsing.
        """
        import random
        jitter = random.randint(min_ms, max_ms) / 1000.0
        time.sleep(jitter)
