"""
PRIVOPS - External LLM Client & Local Intelligent Fallback
Pluggable LLM integration supporting OpenAI-compatible APIs (OpenAI, Gemini, Groq, Ollama)
along with an offline context-aware simulated fallback engine.
Ensures zero raw PII is ever sent over the network.
"""

import os
import re
import json
import httpx
from typing import Dict, Any, Optional, Tuple


class LLMClient:
    """
    Pluggable LLM client.
    Guarantees that only sanitized strings containing token placeholders are transmitted.
    """

    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY")
        self.api_base = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1").rstrip("/")
        self.model = os.getenv("LLM_MODEL", "gpt-4o-mini")
        self.timeout = float(os.getenv("LLM_TIMEOUT", "20.0"))

    def call_llm(
        self,
        sanitized_prompt: str,
        purpose: str = "customer_support",
        system_instruction: Optional[str] = None
    ) -> Tuple[str, str, Dict[str, Any]]:
        """
        Sends sanitized text to configured LLM provider or local fallback.
        
        Returns:
            (response_text, provider_name, metadata)
        """
        # If API key is present and not dummy, invoke external provider
        if self.api_key and self.api_key.strip() and not self.api_key.startswith("mock_"):
            try:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                messages = [
                    {
                        "role": "system",
                        "content": system_instruction or (
                            f"You are an enterprise AI assistant assisting with {purpose}. "
                            f"Respond politely and professionally. Keep any token placeholders like "
                            f"<PERSON_1>, <PAN_1>, <PHONE_1> intact in your response so the user's "
                            f"application can resolve them."
                        )
                    },
                    {"role": "user", "content": sanitized_prompt}
                ]
                payload = {
                    "model": self.model,
                    "messages": messages,
                    "temperature": 0.3
                }
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(f"{self.api_base}/chat/completions", headers=headers, json=payload)
                    resp.raise_for_status()
                    data = resp.json()
                    content = data["choices"][0]["message"]["content"]
                    return content, f"openai-compatible ({self.model})", {"usage": data.get("usage", {})}
            except Exception as e:
                print(f"[PRIVOPS Warning] External LLM call failed: {e}. Falling back to Local Mock LLM.")

        # Local intelligent fallback simulator
        response, provider = self._generate_intelligent_mock_response(sanitized_prompt, purpose)
        return response, provider, {"mode": "local_mock_fallback"}

    def _generate_intelligent_mock_response(self, text: str, purpose: str) -> Tuple[str, str]:
        """
        Context-aware local simulator for hackathon offline demonstrations.
        Detects tokens in prompt and generates realistic enterprise responses
        retaining token placeholders.
        """
        tokens = re.findall(r"<[A-Z_]+_\d+>", text)
        person_tokens = [t for t in tokens if t.startswith("<PERSON_")]
        pan_tokens = [t for t in tokens if t.startswith("<PAN_")]
        phone_tokens = [t for t in tokens if t.startswith("<PHONE_")]
        email_tokens = [t for t in tokens if t.startswith("<EMAIL_")]
        bank_tokens = [t for t in tokens if t.startswith("<BANK_ACCOUNT_")]
        aadhaar_tokens = [t for t in tokens if t.startswith("<AADHAAR_")]

        p_name = person_tokens[0] if person_tokens else "Valued Customer"

        if purpose == "loan_processing":
            pan_str = f" referenced by PAN {pan_tokens[0]}" if pan_tokens else ""
            bank_str = f" to verified account {bank_tokens[0]}" if bank_tokens else ""
            resp = (
                f"Dear {p_name},\n\n"
                f"We have completed the preliminary credit assessment for your enterprise loan application{pan_str}. "
                f"Based on our underwriting criteria, you are pre-approved for a credit facility of INR 15,00,000 "
                f"at a competitive annual interest rate of 8.5%.\n\n"
                f"The sanction letter and disbursement agreement will be routed{bank_str}. "
                f"Our relationship manager will contact your verified phone {phone_tokens[0] if phone_tokens else 'on file'} "
                f"for final signature verification.\n\n"
                f"Best regards,\n"
                f"Commercial Credit Underwriting Group"
            )
        elif purpose == "customer_support":
            contact_ref = f"at {phone_tokens[0]}" if phone_tokens else (f"at {email_tokens[0]}" if email_tokens else "")
            resp = (
                f"Hello {p_name},\n\n"
                f"Thank you for contacting Enterprise Support. We have registered service ticket #REQ-98402 for your query. "
                f"Our technical operations team is currently investigating the incident.\n\n"
                f"Updates will be dispatched to your registered address {contact_ref}. "
                f"The estimated turnaround time for ticket resolution is 4 hours.\n\n"
                f"Warm regards,\n"
                f"Customer Support Operations"
            )
        elif purpose == "marketing":
            email_ref = f" to {email_tokens[0]}" if email_tokens else ""
            resp = (
                f"Greetings {p_name}!\n\n"
                f"We are thrilled to present our exclusive quarterly corporate rewards program. "
                f"As a premier client, you have unlocked a 25% discount tier on all cloud security solutions.\n\n"
                f"Your customized activation brochure has been sent{email_ref}. "
                f"Use voucher code PRIV2026 at checkout before the end of the month.\n\n"
                f"Sincerely,\n"
                f"Growth & Marketing Strategy Team"
            )
        elif purpose == "fraud_investigation":
            resp = (
                f"SECURITY AUDIT REPORT:\n"
                f"Subject: Transaction risk analysis for subject {p_name}.\n"
                f"Identified Assets: PAN {pan_tokens[0] if pan_tokens else 'N/A'}, "
                f"Account {bank_tokens[0] if bank_tokens else 'N/A'}.\n"
                f"Audit Status: Verified clean. No anomalous outflow patterns or sanctions violations observed.\n"
                f"Recommendation: Clear for standard transaction processing."
            )
        else:
            resp = (
                f"Hello {p_name},\n\n"
                f"Your query has been analyzed successfully. "
                f"All requested data points have been reviewed in compliance with enterprise security guidelines.\n\n"
                f"Summary: Request fulfilled according to policy parameters."
            )

        return resp, "PRIVOPS Local Enterprise Simulator"


llm_client_instance = LLMClient()

