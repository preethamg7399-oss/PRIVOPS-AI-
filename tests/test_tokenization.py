"""
Tests for Smart Tokenization and Vault Encryption.
"""

import pytest
from backend.tokenizer import tokenizer_instance
from backend.vault import vault_instance


def test_tokenization_consistency():
    text = "Hello Rahul Kumar, your file is registered under Rahul Kumar and phone 9876543210."
    entities = [
        {"entity_type": "PERSON", "value": "Rahul Kumar", "start": 6, "end": 17, "score": 0.95},
        {"entity_type": "PERSON", "value": "Rahul Kumar", "start": 49, "end": 60, "score": 0.95},
        {"entity_type": "PHONE_NUMBER", "value": "9876543210", "start": 71, "end": 81, "score": 0.90},
    ]

    sanitized, token_map, records = tokenizer_instance.tokenize(text, entities)

    # Both occurrences of Rahul Kumar must map to the same token <PERSON_1>
    assert "<PERSON_1>" in sanitized
    assert sanitized.count("<PERSON_1>") == 2
    assert "<PHONE_NUMBER_1>" in sanitized
    assert token_map["<PERSON_1>"] == "Rahul Kumar"
    assert token_map["<PHONE_NUMBER_1>"] == "9876543210"
    assert "Rahul Kumar" not in sanitized
    assert "9876543210" not in sanitized


def test_encrypted_vault_storage_and_retrieval():
    req_id = "TEST-REQ-001"
    token_map = {"<PERSON_1>": "Siddharth Verma", "<PAN_1>": "ABCDE1234F"}

    # Store in vault
    vault_instance.store_mapping(req_id, token_map, purpose="loan_processing", ttl_seconds=60)

    # Raw map should NOT be in plaintext in vault_store
    raw_stored_blob = vault_instance._vault_store[req_id]["encrypted_data"]
    assert b"Siddharth Verma" not in raw_stored_blob

    # Retrieve and verify decryption
    retrieved = vault_instance.retrieve_mapping(req_id)
    assert retrieved == token_map

    # Cleanup
    vault_instance.delete_mapping(req_id)
    assert vault_instance.retrieve_mapping(req_id) is None

