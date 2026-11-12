"""
Tests for Document Processing and Gateway Integration.
"""

import pytest
import io
import pypdf
from backend.gateway import gateway_instance
from backend.multilingual_engine import multilingual_engine_instance


def create_sample_pdf_bytes(text: str) -> bytes:
    """Creates an in-memory single-page PDF with the given text using reportlab."""
    from reportlab.pdfgen import canvas
    buf = io.BytesIO()
    c = canvas.Canvas(buf)
    lines = text.split("\n")
    y = 750
    for l in lines:
        c.drawString(100, y, l)
        y -= 20
    c.save()
    buf.seek(0)
    return buf.getvalue()


def test_pdf_document_processing_pipeline():
    sample_text = (
        "LOAN APPLICATION FORM\n"
        "Applicant Name: Rahul Kumar\n"
        "Aadhaar Number: 9876 5432 1012\n"
        "PAN Number: ABCPE1234F\n"
        "Primary Mobile: 9876543210\n"
        "Bank Account No: 501004928172"
    )
    pdf_bytes = create_sample_pdf_bytes(sample_text)

    # Process PDF via gateway
    res = gateway_instance.process_document(
        file_bytes=pdf_bytes,
        filename="test_loan_application.pdf",
        purpose="loan_processing",
        anonymize_faces=True
    )

    assert res["success"] is True
    assert res["filename"] == "test_loan_application.pdf"
    assert res["extraction_method"] == "native_parser"
    assert res["language_info"]["lang_code"] == "en"

    # Gateway result assertions
    gw_res = res["gateway_result"]
    assert gw_res["status"] == "PROTECTED"
    assert "<PERSON_1>" in gw_res["panel_b"]["sanitized_outbound_text"]
    assert "9876 5432 1012" not in gw_res["panel_b"]["sanitized_outbound_text"]
    assert "Rahul Kumar" not in gw_res["panel_b"]["sanitized_outbound_text"]

