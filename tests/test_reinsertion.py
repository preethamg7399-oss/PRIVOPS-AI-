"""
Tests for Secure Response Reinsertion Engine.
"""

import pytest
from backend.reinsertion import reinsertion_engine_instance


def test_successful_reinsertion():
    llm_resp = "Dear <PERSON_1>, your loan application referenced with PAN <PAN_1> is approved."
    token_map = {
        "<PERSON_1>": "Aditya Rao",
        "<PAN_1>": "AAAPR9988K"
    }

    final_text, restored, unknown = reinsertion_engine_instance.reinsert(llm_resp, token_map)

    assert final_text == "Dear Aditya Rao, your loan application referenced with PAN AAAPR9988K is approved."
    assert len(restored) == 2
    assert len(unknown) == 0


def test_reordered_tokens():
    llm_resp = "PAN <PAN_1> belongs to borrower <PERSON_1>."
    token_map = {
        "<PERSON_1>": "Aditya Rao",
        "<PAN_1>": "AAAPR9988K"
    }

    final_text, restored, unknown = reinsertion_engine_instance.reinsert(llm_resp, token_map)
    assert final_text == "PAN AAAPR9988K belongs to borrower Aditya Rao."


def test_unknown_token_flagging():
    # LLM hallucinates <PERSON_99> and <AADHAAR_2>
    llm_resp = "Hello <PERSON_1>, we also reviewed <PERSON_99> and Aadhaar <AADHAAR_2>."
    token_map = {
        "<PERSON_1>": "Aditya Rao"
    }

    final_text, restored, unknown = reinsertion_engine_instance.reinsert(llm_resp, token_map)

    # Known token is restored
    assert "Hello Aditya Rao" in final_text
    # Unknown tokens are NOT fabricated or crash
    assert "<PERSON_99>" in final_text
    assert "<AADHAAR_2>" in final_text
    assert "<PERSON_99>" in unknown
    assert "<AADHAAR_2>" in unknown

