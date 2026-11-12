"""
PRIVOPS - FastAPI Application Entry Point
Production-ready REST API for the Purpose-Aware Privacy Gateway.
"""

from fastapi import FastAPI, HTTPException, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

from backend.gateway import gateway_instance
from backend.detector import detector_instance
from backend.tokenizer import tokenizer_instance
from backend.purpose_engine import purpose_engine_instance
from backend.incident_manager import incident_manager_instance
from backend.audit import audit_logger_instance
from backend.vault import vault_instance
from backend.multilingual_engine import multilingual_engine_instance
from backend.face_anonymizer import face_anonymizer_instance
from backend.dataset_evaluator import dataset_evaluator_instance

app = FastAPI(
    title="PRIVOPS Gateway API",
    description="Purpose-Aware AI Privacy Gateway with Incident Memory - DPDP Compliant",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request & Response Schemas
class GatewayProcessRequest(BaseModel):
    text: str = Field(..., description="Raw text containing potential sensitive PII")
    purpose: str = Field("customer_support", description="Declared purpose of processing")
    client_id: str = Field("enterprise_app", description="Identifier of the enterprise client")
    simulate_leak: bool = Field(False, description="Simulate an outbound leak to test LeakGuard")
    system_prompt: Optional[str] = Field(None, description="Optional custom system prompt")


class DetectOnlyRequest(BaseModel):
    text: str


class PolicyUpdateRequest(BaseModel):
    allowed: Optional[List[str]] = None
    masked: Optional[List[str]] = None
    blocked: Optional[List[str]] = None
    dpdp_clause: Optional[str] = None


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "PRIVOPS Privacy Gateway",
        "version": "1.0.0",
        "vault_active": True,
        "detector_active": True
    }


@app.post("/api/v1/process")
def process_gateway_request(req: GatewayProcessRequest):
    """
    Primary gateway endpoint.
    Performs full 10-step intercept, detect, purpose check, tokenize, vault,
    leak-guard, external LLM call, and safe local reinsertion.
    """
    res = gateway_instance.process_request(
        text=req.text,
        purpose=req.purpose,
        client_id=req.client_id,
        simulate_leak=req.simulate_leak,
        custom_system_prompt=req.system_prompt
    )
    return res


@app.post("/api/v1/detect")
def detect_pii_only(req: DetectOnlyRequest):
    """Detects and classifies PII entities in the provided text without tokenizing."""
    entities = detector_instance.detect_entities(req.text)
    return {
        "total_detected": len(entities),
        "entities": entities
    }


@app.post("/api/v1/sanitize")
def sanitize_only(req: GatewayProcessRequest):
    """Detects, validates purpose, and tokenizes text without invoking external LLM."""
    detected = detector_instance.detect_entities(req.text)
    is_compliant, msg, blocked, clause = purpose_engine_instance.validate_purpose_compliance(req.purpose, detected)
    
    if not is_compliant:
        raise HTTPException(status_code=403, detail={
            "error": "PURPOSE_VIOLATION",
            "message": msg,
            "blocked_entities": blocked,
            "dpdp_clause": clause
        })

    sanitized, token_map, entity_records = tokenizer_instance.tokenize(req.text, detected)
    return {
        "sanitized_text": sanitized,
        "token_map": token_map,
        "entity_records": entity_records
    }


@app.get("/api/v1/incidents")
def list_incidents(
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[str] = Query(None, description="Filter by severity: LOW, MEDIUM, HIGH, CRITICAL")
):
    """Retrieves security incidents logged by the incident memory engine."""
    return incident_manager_instance.get_incidents(limit=limit, severity=severity)


@app.get("/api/v1/incidents/summary")
def get_incidents_summary():
    """Provides aggregated incident statistics and recurring pattern flags."""
    return incident_manager_instance.get_incident_summary()


@app.get("/api/v1/audit/metrics")
def get_audit_metrics():
    """Returns aggregated audit metrics for dashboard charts and compliance reports."""
    return audit_logger_instance.get_metrics_summary()


@app.get("/api/v1/audit/logs")
def get_audit_logs(limit: int = Query(50, ge=1, le=500)):
    """Returns recent audit trail entries."""
    return audit_logger_instance.get_recent_logs(limit=limit)


@app.get("/api/v1/policies")
def list_policies():
    """Returns configured purpose-aware privacy policies."""
    return purpose_engine_instance.get_supported_purposes()


@app.put("/api/v1/policies/{purpose}")
def update_policy(purpose: str, req: PolicyUpdateRequest):
    """Updates a specific purpose policy configuration."""
    update_data = {k: v for k, v in req.dict().items() if v is not None}
    success = purpose_engine_instance.update_policy(purpose, update_data)
    if not success:
        raise HTTPException(status_code=404, detail="Purpose not found")
    return {"status": "updated", "purpose": purpose}


@app.get("/api/v1/vault/status")
def get_vault_status():
    """Returns local privacy vault security telemetry."""
    return vault_instance.get_vault_stats()


# =====================================================================
# NEW PART 8 ENDPOINTS (Documents, Multilingual, Visual, Evaluation)
# =====================================================================

@app.post("/api/documents/upload")
async def upload_document(
    file: UploadFile = File(...)
):
    """Accepts document upload (PDF, PNG, JPG) and extracts text and language."""
    content = await file.read()
    raw_text, method, meta = multilingual_engine_instance.extract_document_text(content, file.filename)
    lang_info = multilingual_engine_instance.identify_language(raw_text)
    return {
        "filename": file.filename,
        "extraction_method": method,
        "metadata": meta,
        "language_info": lang_info,
        "text_preview": raw_text[:500] if raw_text else "",
        "char_count": len(raw_text)
    }


@app.post("/api/documents/process")
async def process_document_endpoint(
    file: UploadFile = File(...),
    purpose: str = Form("loan_processing"),
    client_id: str = Form("api_client"),
    anonymize_faces: bool = Form(True)
):
    """Processes document through the complete PRIVOPS zero-exposure gateway."""
    content = await file.read()
    res = gateway_instance.process_document(
        file_bytes=content,
        filename=file.filename,
        purpose=purpose,
        client_id=client_id,
        anonymize_faces=anonymize_faces
    )
    return res


@app.post("/api/multilingual/detect")
def multilingual_detect_endpoint(req: DetectOnlyRequest):
    """Detects language and Indian regional PII entities across 8 languages."""
    lang_info = multilingual_engine_instance.identify_language(req.text)
    std_detected = detector_instance.detect_entities(req.text)
    multi_detected = multilingual_engine_instance.detect_multilingual_pii(req.text)

    merged = std_detected.copy()
    spans = {(d["start"], d["end"]) for d in std_detected}
    for md in multi_detected:
        if (md["start"], md["end"]) not in spans:
            merged.append(md)
            spans.add((md["start"], md["end"]))

    return {
        "language_info": lang_info,
        "total_detected": len(merged),
        "entities": merged
    }


@app.post("/api/visual/detect-faces")
async def detect_faces_endpoint(file: UploadFile = File(...)):
    """Detects human faces in an image using OpenCV YuNet."""
    import numpy as np
    import cv2
    content = await file.read()
    np_arr = np.frombuffer(content, np.uint8)
    img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
    if img is None:
        raise HTTPException(status_code=400, detail="Invalid image file format.")
    faces = face_anonymizer_instance.detect_faces(img)
    return {
        "filename": file.filename,
        "faces_detected": len(faces),
        "face_coordinates": faces
    }


@app.post("/api/visual/anonymize")
async def anonymize_faces_endpoint(
    file: UploadFile = File(...),
    method: str = Form("blur"),
    blur_factor: int = Form(51),
    pixel_size: int = Form(12)
):
    """Anonymizes faces in an image and returns protected image payload."""
    content = await file.read()
    res = gateway_instance.process_image_visual(
        image_bytes=content,
        filename=file.filename,
        method=method,
        blur_factor=blur_factor,
        pixel_size=pixel_size
    )
    return {
        "request_id": res["request_id"],
        "filename": res["filename"],
        "faces_detected": res["faces_detected"],
        "face_coordinates": res["face_coordinates"],
        "telemetry": res["telemetry"]
    }


@app.post("/api/evaluation/run")
def run_evaluation_endpoint():
    """Runs the 50-document ground-truth benchmark evaluation."""
    report = dataset_evaluator_instance.run_evaluation()
    return report


@app.get("/api/evaluation/results")
def get_evaluation_results_endpoint():
    """Returns the latest evaluation report results."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report_file = os.path.join(base_dir, "dataset", "latest_evaluation_report.json")
    if os.path.exists(report_file):
        import json
        with open(report_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return dataset_evaluator_instance.run_evaluation()


@app.get("/api/audit/logs")
def get_audit_logs_v1(limit: int = Query(50, ge=1, le=500)):
    """Returns recent audit logs."""
    return audit_logger_instance.get_recent_logs(limit=limit)


@app.get("/api/analytics/overview")
def get_analytics_overview():
    """Returns system-wide analytics overview."""
    return audit_logger_instance.get_metrics_summary()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)

