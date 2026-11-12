"""
PRIVOPS - Smart Tokenization Engine
Transforms detected sensitive personal information into deterministic,
type-safe placeholders (e.g. <PERSON_1>, <AADHAAR_1>, <PAN_1>).
Maintains request-wide consistency for repeated entities.
"""

from typing import List, Dict, Any, Tuple


class SmartTokenizer:
    """
    Replaces detected PII spans with consistent placeholders.
    Maintains 1-to-1 mapping per request and ensures character integrity.
    """

    def tokenize(
        self, text: str, entities: List[Dict[str, Any]]
    ) -> Tuple[str, Dict[str, str], List[Dict[str, Any]]]:
        """
        Tokenizes the input text by replacing detected entities with tokens.
        
        Args:
            text: Original raw input text.
            entities: Detected entities with start, end, entity_type, value.
            
        Returns:
            sanitized_text: Text with tokens substituted.
            token_map: Dict mapping token placeholder to raw sensitive value.
            entity_token_records: Metadata list of replaced entities with assigned tokens.
        """
        if not entities or not text:
            return text, {}, []

        # 1. Deduplicate by entity value to ensure consistent token assignment
        # E.g. If "Rahul Kumar" appears twice, both should get <PERSON_1>
        entity_counters: Dict[str, int] = {}
        value_to_token: Dict[Tuple[str, str], str] = {}  # (entity_type, clean_value) -> token
        token_to_value: Dict[str, str] = {}  # token -> raw_value

        entity_token_records: List[Dict[str, Any]] = []

        # Sort entities by start asc to assign numbering in reading order
        sorted_entities = sorted(entities, key=lambda x: x["start"])

        for ent in sorted_entities:
            etype = ent["entity_type"]
            val = ent["value"]
            norm_key = (etype, val.strip().lower())

            if norm_key in value_to_token:
                assigned_token = value_to_token[norm_key]
            else:
                curr_count = entity_counters.get(etype, 0) + 1
                entity_counters[etype] = curr_count
                assigned_token = f"<{etype}_{curr_count}>"
                value_to_token[norm_key] = assigned_token
                token_to_value[assigned_token] = val

            entity_token_records.append({
                "token": assigned_token,
                "entity_type": etype,
                "raw_value": val,
                "start": ent["start"],
                "end": ent["end"],
                "score": ent.get("score", 1.0)
            })

        # 2. Replace tokens in text from right to left (reverse start order)
        # to preserve indices of earlier occurrences
        sorted_for_replacement = sorted(entity_token_records, key=lambda x: x["start"], reverse=True)
        sanitized_chars = list(text)

        for rec in sorted_for_replacement:
            s = rec["start"]
            e = rec["end"]
            token_str = rec["token"]
            sanitized_chars[s:e] = list(token_str)

        sanitized_text = "".join(sanitized_chars)

        return sanitized_text, token_to_value, entity_token_records


tokenizer_instance = SmartTokenizer()

