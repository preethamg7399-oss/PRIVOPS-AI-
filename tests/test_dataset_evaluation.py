"""
Tests for Dataset-Based PII Evaluation Benchmark.
"""

import pytest
import os
from backend.dataset_evaluator import dataset_evaluator_instance


def test_dataset_generation_and_structure():
    docs = dataset_evaluator_instance.generate_and_save_dataset()
    assert len(docs) == 50
    first_doc = docs[0]

    assert "doc_id" in first_doc
    assert "doc_type" in first_doc
    assert "language" in first_doc
    assert "original_text" in first_doc
    assert "expected_entities" in first_doc
    assert "expected_sanitized_output" in first_doc
    assert len(first_doc["expected_entities"]) >= 3


def test_dataset_evaluation_metrics():
    report = dataset_evaluator_instance.run_evaluation()

    assert report["total_documents"] == 50
    assert report["precision_percentage"] > 75.0
    assert report["recall_percentage"] > 85.0
    assert report["f1_score_percentage"] > 80.0
    assert "document_breakdown" in report
    assert len(report["document_breakdown"]) == 50


def test_custom_dataset_input_evaluation():
    custom_records = [
        {
            "doc_id": "TEST-CUSTOM-001",
            "doc_type": "Loan Form",
            "language": "en",
            "original_text": "Customer: Sunita Verma, Aadhaar: 8952 1816 1436, Phone: 9811023456",
            "expected_entities": [
                {"category": "PERSON", "value": "Sunita Verma"},
                {"category": "AADHAAR", "value": "8952 1816 1436"},
                {"category": "PHONE_NUMBER", "value": "9811023456"}
            ]
        }
    ]
    report = dataset_evaluator_instance.run_evaluation(custom_docs=custom_records)
    assert report["total_documents"] == 1
    assert report["precision_percentage"] >= 90.0
    assert report["recall_percentage"] >= 90.0
    assert report["f1_score_percentage"] >= 90.0


def test_interactive_single_input_evaluation():
    text = "Name: Rahul Sharma, Aadhaar: 8952 1816 1436, PAN: ABCPS1234K"
    expected = ["PERSON", "AADHAAR", "PAN"]
    res = dataset_evaluator_instance.evaluate_single_input(text, expected)
    assert res["true_positives"] >= 2
    assert res["precision"] > 50.0
    assert res["recall"] > 50.0

