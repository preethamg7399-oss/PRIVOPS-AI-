"""
PRIVOPS - Secure Response Reinsertion Engine
Restores original personal information safely within the local environment
upon receiving the sanitized AI response from the external LLM.
"""

import re
from typing import Dict, Any, List, Tuple


class ReinsertionEngine:
    """
    Local reinsertion engine:
    1. Replaces authorized tokens with decrypted original values.
    2. Handles reordered or paraphrased tokens.
    3. Prevents cross-mapping across different entities.
    4. Detects and flags hallucinated or unrecognized placeholders.
    """

    TOKEN_PATTERN = re.compile(r"<([A-Z_]+_\d+)>")

    def reinsert(
        self, llm_response: str, token_map: Dict[str, str]
    ) -> Tuple[str, List[Dict[str, Any]], List[str]]:
        """
        Restores token placeholders with original PII from local vault.
        
        Args:
            llm_response: Text received from external LLM containing tokens.
            token_map: Decrypted token-to-raw-value map from local vault.
            
        Returns:
            final_text: Restored user-facing text.
            restored_records: List of successfully restored token details.
            unknown_tokens: List of unknown/hallucinated tokens that were NOT replaced.
        """
        if not llm_response:
            return "", [], []

        if not token_map:
            # If no mapping exists (e.g. general query with no PII), return as is
            return llm_response, [], []

        restored_records: List[Dict[str, Any]] = []
        unknown_tokens: List[str] = []

        def replace_callback(match: re.Match) -> str:
            full_token = match.group(0)  # e.g. "<PERSON_1>"
            
            if full_token in token_map:
                original_val = token_map[full_token]
                restored_records.append({
                    "token": full_token,
                    "restored_value": original_val,
                    "status": "RESTORED"
                })
                return original_val
            else:
                # Token was not in the original vault mapping (LLM hallucination or tampering)
                unknown_tokens.append(full_token)
                # Keep original placeholder without inventing values
                return full_token

        final_text = self.TOKEN_PATTERN.sub(replace_callback, llm_response)

        return final_text, restored_records, unknown_tokens


reinsertion_engine_instance = ReinsertionEngine()

