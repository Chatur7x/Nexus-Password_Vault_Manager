"""
NEXUS Cryptographic Audit Trail (9.6)

Implements:
- Tamper-Evident Log (Hash Chain / Mini-Blockchain)
- Signed Access Receipts with timestamps
- Anomaly Detection on access patterns
"""

import os
import json
import hashlib
import time
import statistics
from datetime import datetime, timezone, timedelta
from collections import defaultdict

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
AUDIT_DIR = os.path.join(DATA_DIR, 'audit')
os.makedirs(AUDIT_DIR, exist_ok=True)

AUDIT_LOG_FILE = os.path.join(AUDIT_DIR, 'chain.jsonl')
ANOMALY_FILE = os.path.join(AUDIT_DIR, 'anomaly_baseline.json')


class HashChainAuditLog:
    """
    Every vault access event is hashed and chained to the previous event.
    If any event is deleted, modified, or inserted out of order,
    the chain breaks and the tampering is immediately detectable.
    
    Structure: each entry contains:
    - event data (action, target, timestamp)
    - hash of the previous entry
    - hash of (previous_hash + current_data)
    """

    def __init__(self):
        self.chain = self._load_chain()

    def _load_chain(self) -> list[dict]:
        """Load existing audit chain from disk."""
        chain = []
        if os.path.exists(AUDIT_LOG_FILE):
            with open(AUDIT_LOG_FILE, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        chain.append(json.loads(line))
        return chain

    def _save_entry(self, entry: dict):
        """Append a single entry to the chain file."""
        with open(AUDIT_LOG_FILE, 'a') as f:
            f.write(json.dumps(entry) + "\n")

    def _compute_hash(self, data: str, previous_hash: str) -> str:
        """Compute the chained hash for an entry."""
        return hashlib.sha256(f"{previous_hash}:{data}".encode()).hexdigest()

    def log_event(self, action: str, target: str, details: dict = None):
        """
        Log an access event to the tamper-evident chain.
        
        action: "read", "write", "delete", "share", "export", "unlock", "lock"
        target: The vault entry title or system component accessed
        details: Optional additional metadata
        """
        previous_hash = self.chain[-1]["hash"] if self.chain else "GENESIS"

        event_data = {
            "action": action,
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "epoch": int(time.time()),
            "details": details or {}
        }

        data_str = json.dumps(event_data, sort_keys=True)
        current_hash = self._compute_hash(data_str, previous_hash)

        entry = {
            "sequence": len(self.chain),
            "previous_hash": previous_hash,
            "data": event_data,
            "hash": current_hash
        }

        self.chain.append(entry)
        self._save_entry(entry)

    def verify_chain_integrity(self) -> dict:
        """
        Walk the entire chain and verify every hash link.
        If any entry was tampered with, this detects it.
        """
        if not self.chain:
            return {"valid": True, "entries_checked": 0}

        errors = []

        for i, entry in enumerate(self.chain):
            # Verify link to previous
            expected_prev = self.chain[i-1]["hash"] if i > 0 else "GENESIS"
            if entry["previous_hash"] != expected_prev:
                errors.append({
                    "sequence": i,
                    "error": "broken_chain_link",
                    "expected_previous": expected_prev,
                    "actual_previous": entry["previous_hash"]
                })

            # Verify self-hash
            data_str = json.dumps(entry["data"], sort_keys=True)
            expected_hash = self._compute_hash(data_str, entry["previous_hash"])
            if entry["hash"] != expected_hash:
                errors.append({
                    "sequence": i,
                    "error": "data_tampered",
                    "expected_hash": expected_hash,
                    "actual_hash": entry["hash"]
                })

        return {
            "valid": len(errors) == 0,
            "entries_checked": len(self.chain),
            "errors": errors,
            "chain_length": len(self.chain),
            "first_event": self.chain[0]["data"]["timestamp"] if self.chain else None,
            "last_event": self.chain[-1]["data"]["timestamp"] if self.chain else None
        }

    def get_recent_events(self, count: int = 20) -> list[dict]:
        """Return the most recent N events."""
        return self.chain[-count:]


class SignedAccessReceipt:
    """
    Each credential access generates a signed, timestamped receipt.
    You can prove to an auditor exactly what was accessed and when,
    without revealing the credential itself.
    """

    @staticmethod
    def generate_receipt(
        action: str,
        target: str,
        user_hash: str,
        signing_key: bytes
    ) -> dict:
        """
        Generate a cryptographically signed access receipt.
        The receipt proves the action occurred without revealing the credential value.
        """
        receipt_data = {
            "action": action,
            "target_hash": hashlib.sha256(target.encode()).hexdigest(),
            "user_hash": user_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "epoch": int(time.time()),
            "nonce": hashlib.sha256(os.urandom(16)).hexdigest()[:16]
        }

        # Sign the receipt with HMAC-SHA256
        data_str = json.dumps(receipt_data, sort_keys=True)
        import hmac
        signature = hmac.new(
            signing_key,
            data_str.encode(),
            hashlib.sha256
        ).hexdigest()

        return {
            "receipt": receipt_data,
            "signature": signature
        }

    @staticmethod
    def verify_receipt(receipt: dict, signing_key: bytes) -> bool:
        """Verify the signature on an access receipt."""
        import hmac
        data_str = json.dumps(receipt["receipt"], sort_keys=True)
        expected_sig = hmac.new(
            signing_key,
            data_str.encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected_sig, receipt["signature"])


class AccessAnomalyDetector:
    """
    Detects unusual access patterns on vault credentials.
    
    If a credential normally accessed once a week is suddenly accessed
    50 times in an hour, the system flags it as suspicious.
    
    Uses a simple statistical model: if the access rate exceeds
    3 standard deviations from the historical mean, trigger an alert.
    """

    def __init__(self):
        self.baseline_path = ANOMALY_FILE
        self.baselines = self._load_baselines()

    def _load_baselines(self) -> dict:
        if os.path.exists(self.baseline_path):
            with open(self.baseline_path, 'r') as f:
                return json.load(f)
        return {}

    def _save_baselines(self):
        os.makedirs(AUDIT_DIR, exist_ok=True)
        with open(self.baseline_path, 'w') as f:
            json.dump(self.baselines, f, indent=2)

    def record_access(self, target: str):
        """Record an access event for a credential."""
        if target not in self.baselines:
            self.baselines[target] = {
                "hourly_counts": [],
                "current_hour": None,
                "current_count": 0
            }

        baseline = self.baselines[target]
        current_hour = datetime.now(timezone.utc).strftime("%Y%m%d%H")

        if baseline["current_hour"] == current_hour:
            baseline["current_count"] += 1
        else:
            # Archive the previous hour's count
            if baseline["current_hour"] is not None:
                baseline["hourly_counts"].append(baseline["current_count"])
                # Keep last 720 hours (30 days) of data
                baseline["hourly_counts"] = baseline["hourly_counts"][-720:]
            baseline["current_hour"] = current_hour
            baseline["current_count"] = 1

        self._save_baselines()

    def check_anomaly(self, target: str) -> dict:
        """
        Check if the current access rate for a credential is anomalous.
        Returns alert status and details.
        """
        baseline = self.baselines.get(target)
        if not baseline or len(baseline["hourly_counts"]) < 24:
            return {
                "is_anomalous": False,
                "reason": "insufficient_data",
                "target": target
            }

        counts = baseline["hourly_counts"]
        current = baseline["current_count"]

        mean = statistics.mean(counts)
        stdev = statistics.stdev(counts) if len(counts) > 1 else 1.0

        if stdev == 0:
            stdev = 0.5  # Prevent division by zero

        z_score = (current - mean) / stdev

        is_anomalous = z_score > 3.0

        return {
            "is_anomalous": is_anomalous,
            "target": target,
            "current_accesses_this_hour": current,
            "historical_mean": round(mean, 2),
            "historical_stdev": round(stdev, 2),
            "z_score": round(z_score, 2),
            "severity": "critical" if z_score > 5 else "warning" if z_score > 3 else "normal"
        }

    def scan_all(self) -> list[dict]:
        """Scan all tracked credentials for anomalies."""
        alerts = []
        for target in self.baselines:
            result = self.check_anomaly(target)
            if result["is_anomalous"]:
                alerts.append(result)
        return alerts
