"""
PRIVOPS - Rigorous Evaluation Benchmark Runner
Evaluates 50+ synthetic Indian enterprise documents across 7 key metrics:
1. PII Detection Precision
2. PII Detection Recall & F1
3. Tokenization Accuracy
4. Reinsertion Accuracy
5. Outbound PII Leakage Rate (0.0% Target)
6. Purpose-based Request Blocking Accuracy
7. End-to-end Processing Latency
"""

import time
import json
from typing import Dict, Any, List
from dataset.synthetic_data_generator import generate_synthetic_documents
from backend.gateway import gateway_instance
from backend.detector import detector_instance


def run_evaluation(num_docs: int = 50) -> Dict[str, Any]:
    print(f"\n=======================================================")
    print(f"  PRIVOPS BENCHMARK EVALUATION ({num_docs} Synthetic Documents)")
    print(f"=======================================================\n")

    docs = generate_synthetic_documents(num_docs)

    total_expected_entities = 0
    total_detected_entities = 0
    true_positives = 0
    false_positives = 0
    false_negatives = 0

    tokenization_success_count = 0
    total_tokenization_attempts = 0

    reinsertion_success_count = 0
    total_reinsertion_attempts = 0

    leaks_detected_in_outbound = 0
    total_leak_tested_requests = 0

    blocking_test_passed = 0
    total_blocking_tests = 0

    latencies_ms: List[float] = []

    for i, doc in enumerate(docs):
        doc_text = doc["text"]
        expected = doc["expected_entities"]
        purpose = doc["purpose"]

        t_start = time.time()

        # 1. Detection Evaluation
        detected = detector_instance.detect_entities(doc_text)
        detected_types = [d["entity_type"] for d in detected]
        expected_types = [e["type"] for e in expected]

        total_expected_entities += len(expected_types)
        total_detected_entities += len(detected_types)

        # Match detected with expected by type
        matched_expected = set()
        doc_tp = 0
        for d in detected:
            dtype = d["entity_type"]
            for idx, exp in enumerate(expected):
                if idx not in matched_expected and exp["type"] == dtype:
                    matched_expected.add(idx)
                    doc_tp += 1
                    break

        doc_fp = len(detected) - doc_tp
        doc_fn = len(expected) - len(matched_expected)

        true_positives += doc_tp
        false_positives += doc_fp
        false_negatives += doc_fn

        # 2. End-to-End Gateway Processing
        # Pick purpose that allows the document (e.g. loan_processing or fraud_investigation)
        # to test full tokenization, vault, LLM, and reinsertion
        safe_purpose = "loan_processing" if "AADHAAR" in expected_types else purpose
        res = gateway_instance.process_request(
            text=doc_text,
            purpose=safe_purpose,
            client_id="eval_runner",
            simulate_leak=False
        )
        latency = (time.time() - t_start) * 1000
        latencies_ms.append(latency)

        if res.get("success"):
            # Check Tokenization
            panel_b = res["panel_b"]
            outbound_text = panel_b["sanitized_outbound_text"]
            token_records = panel_b["token_mapping_table"]
            total_tokenization_attempts += len(token_records)

            for rec in token_records:
                if rec["token"] in outbound_text and rec["raw_value"] not in outbound_text:
                    tokenization_success_count += 1

            # Check Reinsertion
            panel_c = res["panel_c"]
            restored = panel_c["restored_tokens"]
            final_text = panel_c["final_reinserted_response"]
            total_reinsertion_attempts += len(restored)

            for rec in restored:
                if rec["restored_value"] in final_text:
                    reinsertion_success_count += 1

            # Zero-leakage check on outbound
            total_leak_tested_requests += 1
            for rec in token_records:
                if rec["raw_value"] in outbound_text:
                    leaks_detected_in_outbound += 1

        # 3. Purpose Blocking Test (Every 5th document, test intentional violation)
        if i % 5 == 0:
            total_blocking_tests += 1
            # Marketing purpose strictly blocks Aadhaar, PAN, Bank Account, Address, etc.
            block_res = gateway_instance.process_request(
                text=doc_text,
                purpose="marketing",
                client_id="eval_runner_block_test"
            )
            # If doc has blocked items for marketing, it should block
            if block_res.get("status") == "BLOCKED" and block_res.get("block_reason") == "PURPOSE_DATA_MINIMIZATION_VIOLATION":
                blocking_test_passed += 1
            elif block_res.get("success") and not any(t in ["AADHAAR", "PAN", "BANK_ACCOUNT", "ADDRESS", "GSTIN", "VOTER_ID", "PASSPORT"] for t in detected_types):
                # Document genuinely had no blocked items, so passing is correct
                blocking_test_passed += 1

        # 4. Intentional Leak Interception Test (Every 7th document)
        if i % 7 == 0:
            total_blocking_tests += 1
            # Use fraud_investigation purpose so all entities are allowed through step 2, testing LeakGuard at step 5
            leak_res = gateway_instance.process_request(
                text=doc_text,
                purpose="fraud_investigation",
                client_id="eval_runner_leak_test",
                simulate_leak=True
            )
            if leak_res.get("status") in ["LEAK_PREVENTED", "BLOCKED"]:
                blocking_test_passed += 1

    # Metrics calculation
    precision = (true_positives / (true_positives + false_positives)) if (true_positives + false_positives) > 0 else 0.0
    recall = (true_positives / (true_positives + false_negatives)) if (true_positives + false_negatives) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    tokenization_acc = (tokenization_success_count / total_tokenization_attempts) if total_tokenization_attempts > 0 else 1.0
    reinsertion_acc = (reinsertion_success_count / total_reinsertion_attempts) if total_reinsertion_attempts > 0 else 1.0
    leakage_rate = (leaks_detected_in_outbound / total_leak_tested_requests) if total_leak_tested_requests > 0 else 0.0
    blocking_acc = (blocking_test_passed / total_blocking_tests) if total_blocking_tests > 0 else 1.0
    avg_latency = sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0

    report = {
        "dataset_size_documents": num_docs,
        "total_expected_entities": total_expected_entities,
        "total_detected_entities": total_detected_entities,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "pii_detection_precision": round(precision * 100, 2),
        "pii_detection_recall": round(recall * 100, 2),
        "pii_detection_f1_score": round(f1 * 100, 2),
        "tokenization_accuracy": round(tokenization_acc * 100, 2),
        "reinsertion_accuracy": round(reinsertion_acc * 100, 2),
        "outbound_pii_leakage_rate": round(leakage_rate * 100, 2),
        "request_blocking_accuracy": round(blocking_acc * 100, 2),
        "average_processing_latency_ms": round(avg_latency, 2)
    }

    print(f"| Metric                              | Measured Score | Target/Standard |")
    print(f"|-------------------------------------|----------------|-----------------|")
    print(f"| PII Detection Precision             | {report['pii_detection_precision']}%         | > 90%           |")
    print(f"| PII Detection Recall                | {report['pii_detection_recall']}%         | > 90%           |")
    print(f"| PII Detection F1-Score              | {report['pii_detection_f1_score']}%         | > 90%           |")
    print(f"| Tokenization Accuracy               | {report['tokenization_accuracy']}%        | 100%            |")
    print(f"| Reinsertion Accuracy                | {report['reinsertion_accuracy']}%        | > 98%           |")
    print(f"| Outbound PII Leakage Rate           | {report['outbound_pii_leakage_rate']}%          | 0.0% (Zero Leak)|")
    print(f"| Request Blocking Accuracy           | {report['request_blocking_accuracy']}%        | 100%            |")
    print(f"| Average Processing Latency          | {report['average_processing_latency_ms']} ms      | < 500 ms        |")
    print(f"=======================================================\n")

    with open("evaluation_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return report


if __name__ == "__main__":
    run_evaluation(50)
