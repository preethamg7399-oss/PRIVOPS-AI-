"""
PRIVOPS - Purpose-Aware Privacy Engine
Implements Section 6 of India's Digital Personal Data Protection (DPDP) Act, 2023:
Purpose Specification and Data Minimization.
Enforces purpose-based access control, classifying PII as ALLOWED, MASKED, or BLOCKED.
"""

import os
import json
from typing import Dict, Any, List, Tuple, Optional


class PurposeViolation(Exception):
    """Raised when request PII violates purpose minimization policies."""
    def __init__(self, message: str, purpose: str, blocked_entities: List[str], dpdp_clause: str):
        super().__init__(message)
        self.purpose = purpose
        self.blocked_entities = blocked_entities
        self.dpdp_clause = dpdp_clause


class PurposeEngine:
    """
    Evaluates requests against purpose policies.
    Determines whether the presence of specific PII categories is legitimate
    for the stated processing purpose.
    """

    def __init__(self, config_path: Optional[str] = None):
        if not config_path:
            # Default to config/policies.json
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            config_path = os.path.join(base_dir, "config", "policies.json")

        self.config_path = config_path
        self.policies: Dict[str, Any] = {}
        self.load_policies()

    def load_policies(self):
        """Loads or reloads policies from policies.json."""
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.policies = data.get("policies", {})
                self.dpdp_alignment = data.get("dpdp_alignment", "")
        except Exception as e:
            print(f"[PRIVOPS Warning] Failed to load policy config: {e}. Using fallback defaults.")
            self._load_fallback_defaults()

    def _load_fallback_defaults(self):
        self.dpdp_alignment = "DPDP Act 2023 - Section 6"
        self.policies = {
            "customer_support": {
                "display_name": "Customer Support",
                "allowed": ["PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS"],
                "masked": ["PAN", "ADDRESS"],
                "blocked": ["AADHAAR", "BANK_ACCOUNT", "PASSPORT", "VOTER_ID", "GSTIN"],
                "dpdp_clause": "Section 6(1) - Processing strictly necessary for support ticket resolution."
            },
            "loan_processing": {
                "display_name": "Loan Processing",
                "allowed": ["PERSON", "PAN", "BANK_ACCOUNT", "PHONE_NUMBER", "EMAIL_ADDRESS", "ADDRESS"],
                "masked": ["AADHAAR", "GSTIN"],
                "blocked": ["PASSPORT", "VOTER_ID"],
                "dpdp_clause": "Section 6(2) - KYC & Credit risk assessment."
            },
            "marketing": {
                "display_name": "Marketing",
                "allowed": ["PERSON", "EMAIL_ADDRESS"],
                "masked": ["PHONE_NUMBER"],
                "blocked": ["AADHAAR", "PAN", "BANK_ACCOUNT", "PASSPORT", "VOTER_ID", "GSTIN", "ADDRESS"],
                "dpdp_clause": "Section 6(1) - Strict Data Minimization; financial and identity credentials strictly prohibited."
            },
            "fraud_investigation": {
                "display_name": "Fraud Investigation",
                "allowed": ["PERSON", "PAN", "BANK_ACCOUNT", "PHONE_NUMBER", "EMAIL_ADDRESS", "GSTIN", "AADHAAR"],
                "masked": ["PASSPORT", "VOTER_ID", "ADDRESS"],
                "blocked": [],
                "dpdp_clause": "Section 17(1)(c) - Prevention and detection of financial fraud."
            },
            "general_inquiry": {
                "display_name": "General Inquiry",
                "allowed": ["PERSON"],
                "masked": ["EMAIL_ADDRESS"],
                "blocked": ["AADHAAR", "PAN", "BANK_ACCOUNT", "PASSPORT", "VOTER_ID", "GSTIN", "PHONE_NUMBER", "ADDRESS"],
                "dpdp_clause": "Section 6 - Minimization; no personal identifiers allowed in general LLM queries."
            }
        }

    def get_supported_purposes(self) -> List[Dict[str, Any]]:
        """Returns metadata for all available purposes."""
        res = []
        for p_id, p_info in self.policies.items():
            res.append({
                "id": p_id,
                "name": p_info.get("display_name", p_id),
                "description": p_info.get("description", ""),
                "allowed": p_info.get("allowed", []),
                "masked": p_info.get("masked", []),
                "blocked": p_info.get("blocked", []),
                "dpdp_clause": p_info.get("dpdp_clause", "")
            })
        return res

    def validate_purpose_compliance(
        self, purpose: str, detected_entities: List[Dict[str, Any]]
    ) -> Tuple[bool, Optional[str], List[str], str]:
        """
        Validates if detected entities conform to the specified processing purpose.
        
        Returns:
            (is_compliant, violation_message, blocked_types_found, dpdp_clause)
        """
        if purpose not in self.policies:
            # Default to strict general_inquiry if unknown purpose
            purpose = "general_inquiry"

        policy = self.policies[purpose]
        blocked_set = set(policy.get("blocked", []))
        dpdp_clause = policy.get("dpdp_clause", "DPDP Act 2023 - Data Minimization")

        # Find detected entity types that are blocked
        detected_types = {e["entity_type"] for e in detected_entities}
        blocked_found = list(detected_types.intersection(blocked_set))

        if blocked_found:
            msg = (
                f"DPDP Purpose Violation: The requested purpose '{policy.get('display_name', purpose)}' "
                f"strictly forbids processing of [{', '.join(blocked_found)}] under {dpdp_clause}. "
                f"Request was blocked to uphold Data Minimization principles."
            )
            return False, msg, blocked_found, dpdp_clause

        return True, None, [], dpdp_clause

    def update_policy(self, purpose: str, updated_data: Dict[str, Any]) -> bool:
        """Dynamically updates purpose policy configuration."""
        if purpose in self.policies:
            self.policies[purpose].update(updated_data)
            try:
                with open(self.config_path, "w", encoding="utf-8") as f:
                    json.dump({"version": "1.0.0", "dpdp_alignment": self.dpdp_alignment, "policies": self.policies}, f, indent=2)
                return True
            except Exception as e:
                print(f"[PRIVOPS Error] Failed to persist policy: {e}")
        return False


purpose_engine_instance = PurposeEngine()

