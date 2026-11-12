"""
PRIVOPS - Intelligent PII Detection Engine
Combines Microsoft Presidio Analyzer, spaCy NER, and custom Indian PII recognizers
to identify Aadhaar, PAN, GSTIN, Voter ID, Passport, Phone, Email, Bank A/C, Address, and Names.
"""

import os
import re
from typing import List, Dict, Any, Optional

# Disable network calls in tldextract before importing Presidio
import tldextract
tldextract.tldextract._GLOBAL_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

import spacy
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

from backend.recognizers import IndianPIIRecognizers, validate_verhoeff


class PIIDetectionEngine:
    """
    Intelligent PII Detection Engine combining:
    1. Microsoft Presidio Analyzer (spacy en_core_web_sm backend)
    2. Custom Indian PII Recognizers (Aadhaar Verhoeff, PAN, GSTIN, Voter ID, Passport, IFSC)
    3. Context-aware Name and Address extraction
    4. Span conflict resolver with priority ranking
    """

    # Priority rank for resolving overlapping entity spans (higher = higher priority)
    ENTITY_PRIORITY = {
        "AADHAAR": 100,
        "GSTIN": 95,
        "PAN": 90,
        "PASSPORT": 85,
        "VOTER_ID": 80,
        "BANK_ACCOUNT": 75,
        "EMAIL_ADDRESS": 70,
        "PHONE_NUMBER": 65,
        "ADDRESS": 60,
        "PERSON": 50,
        "LOCATION": 40,
        "DATE_TIME": 20,
    }

    def __init__(self):
        # 1. Initialize local spaCy NLP pipeline safely
        # Note: In Python 3.12/3.13, debugpy's sys.monitoring tracer has an incompatibility with Cython (.pyx) modules
        # Temporarily disabling sys.monitoring and sys.settrace during model load prevents debugpy's AssertionError in multitask.pyx
        import sys
        saved_mon_events = {}
        if hasattr(sys, "monitoring"):
            for tid in range(6):
                try:
                    ev = sys.monitoring.get_events(tid)
                    if ev:
                        saved_mon_events[tid] = ev
                        sys.monitoring.set_events(tid, 0)
                except Exception:
                    pass

        tracer = sys.gettrace()
        try:
            sys.settrace(None)
            self.nlp = spacy.load("en_core_web_sm")
        except (Exception, BaseException) as e:
            print(f"[PRIVOPS Notice] spaCy loading bypassed (debugger active): {e}")
            self.nlp = None
        finally:
            if tracer:
                sys.settrace(tracer)
            if hasattr(sys, "monitoring"):
                for tid, ev in saved_mon_events.items():
                    try:
                        sys.monitoring.set_events(tid, ev)
                    except Exception:
                        pass

        # 2. Initialize Presidio Analyzer with local configuration
        if self.nlp is not None:
            saved_mon_events_presidio = {}
            if hasattr(sys, "monitoring"):
                for tid in range(6):
                    try:
                        ev = sys.monitoring.get_events(tid)
                        if ev:
                            saved_mon_events_presidio[tid] = ev
                            sys.monitoring.set_events(tid, 0)
                    except Exception:
                        pass
            try:
                sys.settrace(None)
                nlp_config = {
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
                }
                provider = NlpEngineProvider(nlp_configuration=nlp_config)
                self.analyzer = AnalyzerEngine(nlp_engine=provider.create_engine())
            except (Exception, BaseException) as e:
                print(f"[PRIVOPS Warning] Presidio initialized in fallback mode: {e}")
                self.analyzer = None
            finally:
                if tracer:
                    sys.settrace(tracer)
                if hasattr(sys, "monitoring"):
                    for tid, ev in saved_mon_events_presidio.items():
                        try:
                            sys.monitoring.set_events(tid, ev)
                        except Exception:
                            pass
        else:
            self.analyzer = None

        self.recognizers = IndianPIIRecognizers()

    def detect_entities(self, text: str) -> List[Dict[str, Any]]:
        """
        Runs comprehensive PII detection across all recognizers and returns
        deduplicated, sorted list of detected personal entities.
        """
        if not text or not text.strip():
            return []

        raw_candidates: List[Dict[str, Any]] = []

        # 1. Run Indian Domain Recognizers (Deterministic & High-Precision)
        raw_candidates.extend(self.recognizers.find_aadhaar(text))
        raw_candidates.extend(self.recognizers.find_pan(text))
        raw_candidates.extend(self.recognizers.find_gstin(text))
        raw_candidates.extend(self.recognizers.find_voter_id(text))
        raw_candidates.extend(self.recognizers.find_passport(text))
        raw_candidates.extend(self.recognizers.find_phone(text))
        raw_candidates.extend(self.recognizers.find_email(text))
        raw_candidates.extend(self.recognizers.find_bank_account(text))
        raw_candidates.extend(self.recognizers.find_address(text))

        # 2. Run Presidio Analyzer (Email, URL, IP, etc.)
        if self.analyzer:
            try:
                # We target general entities from Presidio
                presidio_results = self.analyzer.analyze(
                    text=text,
                    language="en",
                    entities=["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "IBAN_CODE", "CREDIT_CARD"],
                )
                for res in presidio_results:
                    val = text[res.start:res.end]
                    # Map Presidio types to PRIVOPS types
                    p_type = res.entity_type
                    if p_type == "CREDIT_CARD" or p_type == "IBAN_CODE":
                        p_type = "BANK_ACCOUNT"

                    raw_candidates.append({
                        "entity_type": p_type,
                        "start": res.start,
                        "end": res.end,
                        "value": val,
                        "score": round(res.score, 2),
                        "metadata": {"source": "presidio"}
                    })
            except Exception as e:
                print(f"[PRIVOPS Error] Presidio execution skipped: {e}")

        # 3. Run spaCy NER for Person Names & Indian Context (if available)
        if self.nlp is not None:
            spacy_doc = self.nlp(text)
            for ent in spacy_doc.ents:
                if ent.label_ == "PERSON":
                    val = ent.text.strip()
                    if len(val) >= 2 and not any(ch.isdigit() for ch in val):
                        raw_candidates.append({
                            "entity_type": "PERSON",
                            "start": ent.start_char,
                            "end": ent.end_char,
                            "value": val,
                            "score": 0.88,
                            "metadata": {"source": "spacy_ner"}
                        })

        # 4. Contextual Indian Name Heuristics (e.g. "Name: Rahul Sharma", "Customer: Priya Nair", "Applicant: ...")
        name_context_regex = re.compile(
            r"(?:name|customer|client|patient|applicant|employee|borrower|user|signatory|individual|subject|contact)\s*[:\-]\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})",
            re.IGNORECASE
        )
        for match in name_context_regex.finditer(text):
            val = match.group(1).strip()
            raw_candidates.append({
                "entity_type": "PERSON",
                "start": match.start(1),
                "end": match.end(1),
                "value": val,
                "score": 0.95,
                "metadata": {"source": "contextual_header"}
            })

        # Title-based Indian names (e.g. "Mr. Rahul Kumar", "Dr. Priya Nair")
        title_name_regex = re.compile(
            r"\b(?:Mr\.|Mrs\.|Ms\.|Dr\.|Shri|Smt\.)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2})\b"
        )
        for match in title_name_regex.finditer(text):
            val = match.group(0).strip()
            raw_candidates.append({
                "entity_type": "PERSON",
                "start": match.start(),
                "end": match.end(),
                "value": val,
                "score": 0.92,
                "metadata": {"source": "title_heuristic"}
            })

        # 5. Resolve Overlaps and Deduplicate
        resolved_entities = self._resolve_overlapping_spans(raw_candidates, text)

        return resolved_entities

    def _resolve_overlapping_spans(
        self, candidates: List[Dict[str, Any]], original_text: str
    ) -> List[Dict[str, Any]]:
        """
        Resolves conflicts where multiple recognizers matched overlapping character spans.
        Prioritizes:
        1. Explicit specific entity types (Aadhaar, PAN, GSTIN) over generic ones (Person, Date).
        2. Higher confidence score.
        3. Longer span coverage.
        """
        if not candidates:
            return []

        # Sort primarily by start asc, then by priority desc, then length desc
        def sort_key(c):
            prio = self.ENTITY_PRIORITY.get(c["entity_type"], 10)
            span_len = c["end"] - c["start"]
            return (c["start"], -prio, -c["score"], -span_len)

        sorted_candidates = sorted(candidates, key=sort_key)

        accepted: List[Dict[str, Any]] = []

        for cand in sorted_candidates:
            # Re-verify text slice matches value
            cand_slice = original_text[cand["start"]:cand["end"]]
            if not cand["value"]:
                cand["value"] = cand_slice

            # Check overlap with already accepted entities
            conflict = False
            for existing in accepted:
                # Two spans overlap if max(start1, start2) < min(end1, end2)
                overlap_start = max(cand["start"], existing["start"])
                overlap_end = min(cand["end"], existing["end"])

                if overlap_start < overlap_end:
                    # Overlap detected! Compare priority
                    prio_cand = self.ENTITY_PRIORITY.get(cand["entity_type"], 10)
                    prio_existing = self.ENTITY_PRIORITY.get(existing["entity_type"], 10)

                    # If candidate has higher priority, replace existing
                    if prio_cand > prio_existing:
                        accepted.remove(existing)
                        conflict = False
                        break
                    else:
                        conflict = True
                        break

            if not conflict:
                accepted.append(cand)

        # Final sort by character start index
        accepted.sort(key=lambda x: x["start"])
        return accepted


# Global singleton detector
detector_instance = PIIDetectionEngine()
