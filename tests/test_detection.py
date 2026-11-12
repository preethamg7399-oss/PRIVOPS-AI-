"""
Tests for Intelligent PII Detection Engine and Indian Recognizers.
"""

import pytest
from backend.recognizers import (
    validate_verhoeff,
    generate_verhoeff_checksum,
    IndianPIIRecognizers
)
from backend.detector import detector_instance


def test_verhoeff_aadhaar_validation():
    # Valid Aadhaar generated with Verhoeff
    valid_aadhaar = generate_verhoeff_checksum("98765432101")
    assert len(valid_aadhaar) == 12
    assert validate_verhoeff(valid_aadhaar) is True

    # Corrupting the last digit must fail
    invalid_last_digit = valid_aadhaar[:-1] + str((int(valid_aadhaar[-1]) + 1) % 10)
    assert validate_verhoeff(invalid_last_digit) is False

    # Aadhaar starting with 0 or 1 must fail
    assert validate_verhoeff("012345678901") is False
    assert validate_verhoeff("123456789012") is False


def test_pan_detection():
    text = "Customer PAN is ABCPE1234F and Company PAN is AAACB1234C."
    matches = IndianPIIRecognizers.find_pan(text)
    assert len(matches) == 2
    assert matches[0]["value"] == "ABCPE1234F"
    assert matches[0]["metadata"]["taxpayer_type"] == "Individual"
    assert matches[1]["value"] == "AAACB1234C"
    assert matches[1]["metadata"]["taxpayer_type"] == "Company"


def test_gstin_detection():
    # 15-char GSTIN: 27 (state) + ABCPE1234F (PAN) + 1 (entity) + Z (default) + 5 (checksum)
    text = "Vendor registered under GSTIN 27ABCPE1234F1Z5 and state code 27."
    matches = IndianPIIRecognizers.find_gstin(text)
    assert len(matches) >= 1
    assert matches[0]["value"] == "27ABCPE1234F1Z5"
    assert matches[0]["metadata"]["state_code"] == "27"


def test_phone_and_email_detection():
    text = "Reach Rahul Kumar at rahul.kumar@gmail.com or mobile +91-9876543210 or 08765432109."
    emails = IndianPIIRecognizers.find_email(text)
    phones = IndianPIIRecognizers.find_phone(text)

    assert len(emails) == 1
    assert emails[0]["value"] == "rahul.kumar@gmail.com"

    assert len(phones) == 2
    assert any("9876543210" in p["value"] for p in phones)


def test_comprehensive_detector():
    sample_text = (
        "Applicant: Priya Sharma\n"
        "PAN: BCDPS1234K\n"
        "Phone: 9820112233\n"
        "Email: priya.sharma@example.com\n"
        "Address: Flat 302, Palm Heights, MG Road, Pune, Maharashtra 411004"
    )
    entities = detector_instance.detect_entities(sample_text)
    types_detected = {e["entity_type"] for e in entities}

    assert "PERSON" in types_detected
    assert "PAN" in types_detected
    assert "PHONE_NUMBER" in types_detected
    assert "EMAIL_ADDRESS" in types_detected
