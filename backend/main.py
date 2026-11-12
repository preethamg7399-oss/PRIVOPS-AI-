"""
PRIVOPS - FastAPI Application Entry Point
Production-ready REST API for the Purpose-Aware Privacy Gateway.
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

from backend.gateway import gateway_instance
from backend.detector import detector_instance
from backend.tokenizer import tokenizer_instance
from backend.purpose_engine import purpose_engine_instance
from backend.incident_manager import incident_manager_instance
from backend.audit import audit_logger_instance
from backend.vault import vault_instance

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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)

