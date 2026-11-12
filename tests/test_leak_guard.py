"""
Tests for Zero-Leakage Verification (LeakGuard).
"""

import pytest
from backend.leak_guard import leak_guard_instance


def test_clean_payload_passes():
    sanitized_text = "Hello <PERSON_1>, your inquiry has been processed for PAN <PAN_1>."
    raw_values = ["Rahul Kumar", "ABCDE1234F"]

    is_clean, leaked_items, notes = leak_guard_instance.verify_outbound_payload(
        sanitized_text, raw_values
    )
    assert is_clean is True
    assert len(leaked_items) == 0


def test_direct_leak_fails():
    # Accidental inclusion of raw value
    dirty_text = "Hello <PERSON_1>, your inquiry for Rahul Kumar has been processed."
    raw_values = ["Rahul Kumar", "ABCDE1234F"]

    is_clean, leaked_items, notes = leak_guard_instance.verify_outbound_payload(
        dirty_text, raw_values
    )
    assert is_clean is False
    assert len(leaked_items) >= 1
    assert any("Rahul Kumar" in item for item in leaked_items)


def test_normalized_identifier_leak_fails():
    # Accidental omission of formatting (e.g. 9876543210 inside text)
    dirty_text = "Reference number: 9876543210 is logged."
    raw_values = ["+91 9876543210"]

    is_clean, leaked_items, notes = leak_guard_instance.verify_outbound_payload(
        dirty_text, raw_values
    )
    assert is_clean is False
    assert len(leaked_items) >= 1

