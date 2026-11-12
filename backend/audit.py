"""
PRIVOPS - Audit Logger & Compliance Analytics
Maintains comprehensive, immutable audit trails for every gateway transaction.
Aggregates DPDP compliance metrics, multilingual telemetry, and visual privacy logs.
"""

import os
import sqlite3
import time
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional


class AuditLogger:
    """
    Audit logging engine tracking all transaction lifecycles:
    Text, Document, Multilingual, and Visual Privacy transactions.
    """

    def __init__(self, db_path: Optional[str] = None):
        if not db_path:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            db_path = os.path.join(base_dir, "privops.db")
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initializes the audit logs table with document and visual privacy columns."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    request_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    status TEXT NOT NULL,
                    entities_detected_count INTEGER NOT NULL,
                    pii_types_detected TEXT NOT NULL,
                    tokens_created_count INTEGER NOT NULL,
                    latency_ms REAL NOT NULL,
                    llm_provider TEXT NOT NULL,
                    dpdp_clause TEXT,
                    client_id TEXT NOT NULL,
                    doc_type TEXT DEFAULT 'TEXT',
                    language TEXT DEFAULT 'en',
                    faces_anonymized_count INTEGER DEFAULT 0
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp 
                ON audit_logs(timestamp)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_status 
                ON audit_logs(status)
            """)
            # Schema migration check for existing databases
            cursor.execute("PRAGMA table_info(audit_logs)")
            existing_cols = {row["name"] for row in cursor.fetchall()}
            if "doc_type" not in existing_cols:
                cursor.execute("ALTER TABLE audit_logs ADD COLUMN doc_type TEXT DEFAULT 'TEXT'")
            if "language" not in existing_cols:
                cursor.execute("ALTER TABLE audit_logs ADD COLUMN language TEXT DEFAULT 'en'")
            if "faces_anonymized_count" not in existing_cols:
                cursor.execute("ALTER TABLE audit_logs ADD COLUMN faces_anonymized_count INTEGER DEFAULT 0")
            conn.commit()

    def log_request(
        self,
        request_id: str,
        purpose: str,
        status: str,
        entities_detected_count: int,
        pii_types: List[str],
        tokens_created_count: int,
        latency_ms: float,
        llm_provider: str = "mock-openai",
        dpdp_clause: str = "DPDP Act 2023 - Section 6",
        client_id: str = "default_client",
        doc_type: str = "TEXT",
        language: str = "en",
        faces_anonymized_count: int = 0
    ):
        """Records an audit trail entry for a gateway request."""
        timestamp = datetime.now(timezone.utc).isoformat()
        pii_types_str = ", ".join(sorted(list(set(pii_types)))) if pii_types else "NONE"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO audit_logs 
                (request_id, timestamp, purpose, status, entities_detected_count, 
                 pii_types_detected, tokens_created_count, latency_ms, llm_provider, 
                 dpdp_clause, client_id, doc_type, language, faces_anonymized_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                request_id, timestamp, purpose, status, entities_detected_count,
                pii_types_str, tokens_created_count, round(latency_ms, 2),
                llm_provider, dpdp_clause, client_id, doc_type, language, faces_anonymized_count
            ))
            conn.commit()

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Calculates system-wide aggregate metrics for the audit dashboard."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM audit_logs")
            total_requests = cursor.fetchone()[0]

            cursor.execute("SELECT SUM(entities_detected_count) FROM audit_logs")
            total_entities = cursor.fetchone()[0] or 0

            cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE status = 'PROTECTED'")
            sanitized_success = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE status LIKE 'BLOCKED%'")
            total_blocked = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE status = 'LEAK_PREVENTED'")
            leaks_prevented = cursor.fetchone()[0]

            cursor.execute("SELECT AVG(latency_ms) FROM audit_logs WHERE status = 'PROTECTED'")
            avg_latency = cursor.fetchone()[0] or 0.0

            cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE doc_type != 'TEXT'")
            total_documents = cursor.fetchone()[0] or 0

            cursor.execute("SELECT SUM(faces_anonymized_count) FROM audit_logs")
            total_faces = cursor.fetchone()[0] or 0

            # PII type distribution
            cursor.execute("SELECT pii_types_detected FROM audit_logs WHERE pii_types_detected != 'NONE'")
            rows = cursor.fetchall()
            pii_counts: Dict[str, int] = {}
            for row in rows:
                types = [t.strip() for t in row[0].split(",") if t.strip()]
                for t in types:
                    pii_counts[t] = pii_counts.get(t, 0) + 1

            # Purpose-wise counts
            cursor.execute("SELECT purpose, COUNT(*) FROM audit_logs GROUP BY purpose")
            purpose_counts = dict(cursor.fetchall())

            # Status-wise counts
            cursor.execute("SELECT status, COUNT(*) FROM audit_logs GROUP BY status")
            status_counts = dict(cursor.fetchall())

            # Language-wise counts
            cursor.execute("SELECT language, COUNT(*) FROM audit_logs GROUP BY language")
            lang_counts = dict(cursor.fetchall())

            return {
                "total_requests": total_requests,
                "total_documents_processed": total_documents,
                "total_pii_entities_detected": total_entities,
                "total_faces_anonymized": total_faces,
                "requests_sanitized_success": sanitized_success,
                "requests_blocked": total_blocked,
                "leakage_incidents_prevented": leaks_prevented,
                "average_latency_ms": round(avg_latency, 2),
                "pii_category_frequency": pii_counts,
                "purpose_statistics": purpose_counts,
                "status_statistics": status_counts,
                "language_statistics": lang_counts
            }

    def get_recent_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent audit log records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]


audit_logger_instance = AuditLogger()
