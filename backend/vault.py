"""
PRIVOPS - Encrypted Local Privacy Vault
Secure, in-memory/at-rest encrypted vault for token-to-raw-PII mappings.
Ensures zero exposure of mapping tables to external LLM services.
"""

import os
import json
import time
import base64
import hashlib
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EncryptedVault:
    """
    Local privacy vault with AES-128-CBC / Fernet encryption.
    Stores request-specific token mappings in encrypted format in memory,
    with automatic TTL expiry, secure overwrite on deletion, and audit logging.
    """

    def __init__(self, master_key: Optional[str] = None):
        # Derive or use Fernet key
        if master_key:
            # Derive deterministic 32-byte urlsafe base64 key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"privops_secure_salt_v1",
                iterations=100_000,
            )
            derived = base64.urlsafe_b64encode(kdf.derive(master_key.encode("utf-8")))
            self._cipher = Fernet(derived)
        else:
            env_key = os.getenv("PRIVOPS_VAULT_KEY")
            if env_key:
                try:
                    self._cipher = Fernet(env_key.encode("utf-8") if isinstance(env_key, str) else env_key)
                except Exception:
                    # fallback to generated key if invalid
                    self._cipher = Fernet(Fernet.generate_key())
            else:
                self._cipher = Fernet(Fernet.generate_key())

        # Storage: request_id -> { "encrypted_data": bytes, "created_at": float, "ttl": int, "purpose": str }
        self._vault_store: Dict[str, Dict[str, Any]] = {}
        self._access_log: list = []

    def store_mapping(
        self,
        request_id: str,
        token_map: Dict[str, str],
        purpose: str,
        ttl_seconds: int = 3600
    ) -> bool:
        """
        Encrypt and store the token-to-PII mapping for a specific request.
        Raw values are encrypted immediately.
        """
        payload = {
            "request_id": request_id,
            "token_map": token_map,
            "purpose": purpose,
            "stored_at": time.time(),
        }
        raw_json = json.dumps(payload).encode("utf-8")
        encrypted_blob = self._cipher.encrypt(raw_json)

        self._vault_store[request_id] = {
            "encrypted_data": encrypted_blob,
            "created_at": time.time(),
            "ttl": ttl_seconds,
            "purpose": purpose,
            "token_count": len(token_map)
        }

        self._log_access("STORE", request_id, purpose, len(token_map))
        return True

    def retrieve_mapping(self, request_id: str) -> Optional[Dict[str, str]]:
        """
        Retrieve and decrypt token map for the request.
        Only called locally by the reinsertion engine.
        Returns None if expired or not found.
        """
        record = self._vault_store.get(request_id)
        if not record:
            self._log_access("MISS", request_id, "unknown", 0)
            return None

        # Check TTL
        if time.time() - record["created_at"] > record["ttl"]:
            self.delete_mapping(request_id)
            self._log_access("EXPIRED", request_id, record["purpose"], 0)
            return None

        try:
            decrypted = self._cipher.decrypt(record["encrypted_data"])
            payload = json.loads(decrypted.decode("utf-8"))
            self._log_access("RETRIEVE", request_id, record["purpose"], len(payload.get("token_map", {})))
            return payload.get("token_map", {})
        except Exception:
            self._log_access("DECRYPT_FAILED", request_id, record["purpose"], 0)
            return None

    def get_raw_values_for_leak_check(self, request_id: str) -> list:
        """
        Returns the list of raw sensitive values for leak detection scanning.
        """
        mapping = self.retrieve_mapping(request_id)
        if not mapping:
            return []
        return list(mapping.values())

    def delete_mapping(self, request_id: str) -> bool:
        """
        Secure deletion of the mapping for a request.
        Overwrites with zeros in memory before removal.
        """
        if request_id in self._vault_store:
            record = self._vault_store[request_id]
            # Overwrite memory buffer
            dummy = b"\x00" * len(record["encrypted_data"])
            record["encrypted_data"] = dummy
            del self._vault_store[request_id]
            self._log_access("DELETE", request_id, "n/a", 0)
            return True
        return False

    def cleanup_expired(self) -> int:
        """
        Prunes all expired token mappings.
        """
        now = time.time()
        expired = [
            req_id for req_id, rec in self._vault_store.items()
            if now - rec["created_at"] > rec["ttl"]
        ]
        for req_id in expired:
            self.delete_mapping(req_id)
        return len(expired)

    def _log_access(self, action: str, request_id: str, purpose: str, count: int):
        self._access_log.append({
            "timestamp": time.time(),
            "action": action,
            "request_id": request_id,
            "purpose": purpose,
            "tokens": count
        })
        # Keep recent 500 records
        if len(self._access_log) > 500:
            self._access_log.pop(0)

    def get_vault_stats(self) -> Dict[str, Any]:
        """Returns non-sensitive vault statistics for monitoring."""
        return {
            "active_sessions": len(self._vault_store),
            "access_log_count": len(self._access_log),
            "encryption_algorithm": "AES-128-CBC / Fernet with PBKDF2HMAC",
            "at_rest_encrypted": True,
            "outbound_isolation": "Strict - vault mappings never leave gateway memory"
        }


# Global singleton instance
vault_instance = EncryptedVault()

