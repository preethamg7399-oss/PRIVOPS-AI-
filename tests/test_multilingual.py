"""
Tests for Multilingual Processing, Language Identification, and Regional Indian PII.
"""

import pytest
from backend.multilingual_engine import multilingual_engine_instance


def test_language_identification():
    samples = {
        "en": "Applicant name is Rahul Kumar residing in Bangalore",
        "kn": "ಅರ್ಜಿದಾರ ಹೆಸರು: ರಾಹುಲ್ ಶರ್ಮಾ ಮತ್ತು ದೂರವಾಣಿ ಸಂಖ್ಯೆ 9845012345",
        "hi": "आवेदक का नाम राहुल कुमार है और मोबाइल नंबर 9811023456 है",
        "ta": "விண்ணப்பதாரர் பெயர் பிரியா நாயர் மற்றும் கைபேசி 9840134567",
        "te": "దరఖాస్తుదారు పేరు విక్రమ్ రెడ్డి మరియు మొబైల్ 9849045678",
        "mr": "अर्जदाराचे नाव अमित देशमुख आणि मोबाईल 9822056789 आहे",
        "bn": "আবেদনকারীর নাম সুনীতা বোস এবং ফোন 9830067890"
    }

    for expected_lang, text in samples.items():
        res = multilingual_engine_instance.identify_language(text)
        assert res["lang_code"] == expected_lang
        assert res["supported"] is True


def test_regional_digits_normalization():
    devanagari_digits = "९८७६५४३२१०"
    kannada_digits = "೯೮೭೬೫೪೩೨೧೦"
    bengali_digits = "৯৮৭৬৫৪৩২১০"

    assert multilingual_engine_instance.normalize_regional_digits(devanagari_digits) == "9876543210"
    assert multilingual_engine_instance.normalize_regional_digits(kannada_digits) == "9876543210"
    assert multilingual_engine_instance.normalize_regional_digits(bengali_digits) == "9876543210"


def test_kannada_pii_detection():
    kannada_text = (
        "ಅರ್ಜಿದಾರ ಹೆಸರು: ರಾಹುಲ್ ಶರ್ಮಾ\n"
        "ಆಧಾರ್ ಸಂಖ್ಯೆ: 8952 1816 1436\n"
        "ಪ್ಯಾನ್ ಸಂಖ್ಯೆ: ABCPS1234K\n"
        "ಮೊಬೈಲ್ ಸಂಖ್ಯೆ: 9845012345\n"
        "ವಿಳಾಸ: ಎಂ.ಜಿ. ರಸ್ತೆ, ಬೆಂಗಳೂರು"
    )
    entities = multilingual_engine_instance.detect_multilingual_pii(kannada_text)
    types_found = {e["entity_type"] for e in entities}

    assert "PERSON" in types_found
    assert "AADHAAR" in types_found
    assert "PAN" in types_found
    assert "PHONE_NUMBER" in types_found


def test_hindi_pii_detection():
    hindi_text = (
        "आवेदक का नाम: राहुल कुमार\n"
        "आधार संख्या: 9876 5432 1012\n"
        "पैन कार्ड संख्या: BCDPS1234K\n"
        "मोबाइल नंबर: 9811023456\n"
        "खाता संख्या: 102938475612"
    )
    entities = multilingual_engine_instance.detect_multilingual_pii(hindi_text)
    types_found = {e["entity_type"] for e in entities}

    assert "PERSON" in types_found
    assert "AADHAAR" in types_found
    assert "PAN" in types_found
    assert "PHONE_NUMBER" in types_found
    assert "BANK_ACCOUNT" in types_found

