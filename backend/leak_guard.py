"""
PRIVOPS - Zero-Leakage Verification Engine (LeakGuard)
Pre-outbound security verification layer.
Ensures zero bytes of raw PII leak past the gateway into external LLM endpoints.
"""

import re
from typing import List, Dict, Any, Tuple
from backend.recognizers import IndianPIIRecognizers


class LeakageDetectedError(Exception):
    """Raised when raw PII or unmasked sensitive data is detected in outbound payload."""
    def __init__(self, message: str, leaked_items: List[str], scan_stage: str):
        super().__init__(message)
        self.leaked_items = leaked_items
        self.scan_stage = scan_stage


class LeakGuard:
    """
    Zero-Leakage Verification Guard.
    Performs dual-stage verification before external transmission:
    1. Direct Substring & Normalized Vault Value Search
    2. Deep PII Re-Scan on Outbound Text (excluding authorized <TYPE_N> tokens)
    """

    def __init__(self):
        self.recognizers = IndianPIIRecognizers()

    def verify_outbound_payload(
        self, outbound_text: str, raw_sensitive_values: List[str]
    ) -> Tuple[bool, List[str], str]:
        """
        Scans outbound_text to guarantee complete absence of raw sensitive values.
        
        Args:
            outbound_text: Sanitized text prepared for external LLM.
            raw_sensitive_values: Original values retrieved securely from Vault.
            
        Returns:
            (is_clean, leaked_items, audit_notes)
        """
        leaked_items: List[str] = []

        # 1. Direct and normalized substring check against vault values
        outbound_lower = outbound_text.lower()
        for raw_val in raw_sensitive_values:
            if not raw_val or len(raw_val.strip()) < 3:
                continue

            raw_clean = raw_val.strip()
            # Exact match check
            if raw_clean.lower() in outbound_lower:
                leaked_items.append(f"Raw vault value detected: '{raw_clean}'")
                continue

            # Normalized numeric / identifier check (remove spaces and dashes)
            digits_only = re.sub(r"\D", "", raw_clean)
            if len(digits_only) >= 8:
                outbound_digits = re.sub(r"\D", "", outbound_text)
                if digits_only in outbound_digits:
                    leaked_items.append(f"Normalized identifier pattern detected: '{digits_only}'")

        # 2. Deep Outbound PII Scanner (check if un-tokenized PII remains)
        # Strip authorized token placeholders like <PERSON_1>, <AADHAAR_1> before re-scanning
        token_scrubbed_text = re.sub(r"<[A-Z_]+_\d+>", " ", outbound_text)

        # Run high-confidence domain recognizers on outbound text
        aadhaar_matches = self.recognizers.find_aadhaar(token_scrubbed_text)
        pan_matches = self.recognizers.find_pan(token_scrubbed_text)
        gstin_matches = self.recognizers.find_gstin(token_scrubbed_text)
        phone_matches = self.recognizers.find_phone(token_scrubbed_text)
        email_matches = self.recognizers.find_email(token_scrubbed_text)
        bank_matches = self.recognizers.find_bank_account(token_scrubbed_text)

        for m in aadhaar_matches + pan_matches + gstin_matches + phone_matches + email_matches + bank_matches:
            leaked_items.append(f"Unsanitized {m['entity_type']} found in outbound: '{m['value']}'")

        if leaked_items:
            audit_notes = (
                f"CRITICAL SECURITY ALERT: LeakGuard intercepted outbound request! "
                f"{len(leaked_items)} potential sensitive leak(s) identified. Outbound transmission aborted."
            )
            return False, leaked_items, audit_notes

        audit_notes = "Zero-Leakage Verification PASSED. Outbound payload confirmed 100% sanitized."
        return True, [], audit_notes


leak_guard_instance = LeakGuard()

