"""
PRIVOPS - Core Security Gateway Engine
Orchestrates the 10-step zero-exposure lifecycle:
Validation -> Detection -> Minimization -> Tokenization -> Vault Storage
-> Zero-Leak Verification -> Outbound LLM -> Local Reinsertion -> Incident/Audit Logging
"""

import time
import uuid
from typing import Dict, Any, Optional, List

from backend.detector import detector_instance
from backend.tokenizer import tokenizer_instance
from backend.vault import vault_instance
from backend.purpose_engine import purpose_engine_instance, PurposeViolation
from backend.leak_guard import leak_guard_instance, LeakageDetectedError
from backend.reinsertion import reinsertion_engine_instance
from backend.llm_client import llm_client_instance
from backend.incident_manager import incident_manager_instance
from backend.audit import audit_logger_instance


class PrivOpsGateway:
    """
    The central privacy gateway connecting enterprise apps to external LLMs.
    Guarantees raw PII never crosses outbound boundaries.
    """

    def process_request(
        self,
        text: str,
        purpose: str = "customer_support",
        client_id: str = "axiom_enterprise_client",
        simulate_leak: bool = False,
        custom_system_prompt: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes the full end-to-end PRIVOPS gateway workflow.
        
        Args:
            text: Original raw input text.
            purpose: Declared processing purpose.
            client_id: Requesting client/app ID.
            simulate_leak: If True, simulates intentional raw data leak to test LeakGuard.
            custom_system_prompt: Optional system instruction for LLM.
            
        Returns:
            Structured gateway transaction record with Panel A, Panel B, and Panel C data.
        """
        start_time = time.time()
        request_id = f"REQ-{uuid.uuid4().hex[:10].upper()}"

        # 1. Detect PII in original input
        detected_entities = detector_instance.detect_entities(text)
        detected_types = list({e["entity_type"] for e in detected_entities})

        # 2. Check Purpose & Data Minimization compliance
        is_compliant, violation_msg, blocked_found, dpdp_clause = (
            purpose_engine_instance.validate_purpose_compliance(purpose, detected_entities)
        )

        if not is_compliant:
            latency_ms = (time.time() - start_time) * 1000
            # Record security incident
            incident = incident_manager_instance.record_incident(
                purpose=purpose,
                sensitive_types=blocked_found,
                reason=violation_msg,
                severity="HIGH",
                action_taken="REQUEST_BLOCKED",
                client_id=client_id
            )
            # Log audit
            audit_logger_instance.log_request(
                request_id=request_id,
                purpose=purpose,
                status="BLOCKED_PURPOSE_VIOLATION",
                entities_detected_count=len(detected_entities),
                pii_types=detected_types,
                tokens_created_count=0,
                latency_ms=latency_ms,
                llm_provider="none",
                dpdp_clause=dpdp_clause,
                client_id=client_id
            )
            return {
                "success": False,
                "request_id": request_id,
                "status": "BLOCKED",
                "block_reason": "PURPOSE_DATA_MINIMIZATION_VIOLATION",
                "message": violation_msg,
                "blocked_entities": blocked_found,
                "dpdp_clause": dpdp_clause,
                "incident": incident,
                "original_input": text,
                "detected_entities": detected_entities,
                "latency_ms": round(latency_ms, 2)
            }

        # 3. Smart Tokenization
        sanitized_text, token_map, entity_token_records = tokenizer_instance.tokenize(text, detected_entities)

        # 4. Store encrypted mapping in local privacy vault
        vault_instance.store_mapping(
            request_id=request_id,
            token_map=token_map,
            purpose=purpose,
            ttl_seconds=3600
        )

        # 5. Outbound Leak Detection Scan (Zero-Leakage Verification)
        outbound_payload = sanitized_text

        # Intentional leak injection for demonstration / testing purposes
        if simulate_leak and token_map:
            # Inject one of the raw values back into outbound payload
            first_raw_val = list(token_map.values())[0]
            outbound_payload += f" [LEAK_TEST: Customer Raw Reference: {first_raw_val}]"

        raw_vault_values = vault_instance.get_raw_values_for_leak_check(request_id)
        is_clean, leaked_items, leak_notes = leak_guard_instance.verify_outbound_payload(
            outbound_payload, raw_vault_values
        )

        if not is_clean:
            latency_ms = (time.time() - start_time) * 1000
            # Immediate blocking & incident generation
            incident = incident_manager_instance.record_incident(
                purpose=purpose,
                sensitive_types=detected_types,
                reason=f"Zero-Leakage Verification Failed! Leaked items: {', '.join(leaked_items)}",
                severity="CRITICAL",
                action_taken="OUTBOUND_LEAK_PREVENTED",
                client_id=client_id
            )
            # Log audit
            audit_logger_instance.log_request(
                request_id=request_id,
                purpose=purpose,
                status="LEAK_PREVENTED",
                entities_detected_count=len(detected_entities),
                pii_types=detected_types,
                tokens_created_count=len(token_map),
                latency_ms=latency_ms,
                llm_provider="none (aborted)",
                dpdp_clause=dpdp_clause,
                client_id=client_id
            )
            return {
                "success": False,
                "request_id": request_id,
                "status": "LEAK_PREVENTED",
                "block_reason": "OUTBOUND_LEAK_DETECTED",
                "message": leak_notes,
                "leaked_items": leaked_items,
                "incident": incident,
                "original_input": text,
                "sanitized_outbound": outbound_payload,
                "detected_entities": detected_entities,
                "latency_ms": round(latency_ms, 2)
            }

        # 6. Forward Sanitized Outbound Request to External LLM
        llm_response, provider_name, llm_meta = llm_client_instance.call_llm(
            sanitized_prompt=outbound_payload,
            purpose=purpose,
            system_instruction=custom_system_prompt
        )

        # 7. Secure Local Reinsertion
        decrypted_map = vault_instance.retrieve_mapping(request_id) or {}
        final_reinserted_text, restored_records, unknown_tokens = reinsertion_engine_instance.reinsert(
            llm_response, decrypted_map
        )

        latency_ms = (time.time() - start_time) * 1000

        # 8. Record Successful Audit Log
        audit_logger_instance.log_request(
            request_id=request_id,
            purpose=purpose,
            status="PROTECTED",
            entities_detected_count=len(detected_entities),
            pii_types=detected_types,
            tokens_created_count=len(token_map),
            latency_ms=latency_ms,
            llm_provider=provider_name,
            dpdp_clause=dpdp_clause,
            client_id=client_id
        )

        return {
            "success": True,
            "request_id": request_id,
            "status": "PROTECTED",
            "purpose": purpose,
            "latency_ms": round(latency_ms, 2),
            "llm_provider": provider_name,
            # Panel A
            "panel_a": {
                "original_input": text,
                "detected_entities": detected_entities,
                "total_entities_found": len(detected_entities),
            },
            # Panel B
            "panel_b": {
                "sanitized_outbound_text": outbound_payload,
                "token_mapping_table": entity_token_records,
                "leak_check_status": "PASSED (0 raw bytes leaked)",
                "tokens_generated": len(token_map),
            },
            # Panel C
            "panel_c": {
                "ai_raw_response": llm_response,
                "final_reinserted_response": final_reinserted_text,
                "restored_tokens": restored_records,
                "unknown_tokens_flagged": unknown_tokens,
            },
            "dpdp_compliance": {
                "clause": dpdp_clause,
                "purpose_aligned": True,
                "minimization_status": "ENFORCED",
                "outbound_leak_rate": "0.00%",
                "vault_encryption": "AES-128 / Fernet (At-Rest & Local Memory)"
            }
        }


gateway_instance = PrivOpsGateway()

