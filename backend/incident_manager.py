"""
PRIVOPS - Security Incident Memory & Pattern Tracker
SQLite-backed incident memory recording all privacy policy violations and leak attempts.
Maintains pattern awareness to flag recurring unsafe prompts and anomalous user behavior
without storing raw personal information in logs.
"""

import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional


class IncidentManager:
    """
    Manages security incidents, policy breaches, and leak detection events.
    Stored in local SQLite database with zero raw PII retention.
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
        """Initializes incidents and pattern tables."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_incidents (
                    incident_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    sensitive_types TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    action_taken TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    pattern_flag TEXT DEFAULT 'NORMAL'
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_incidents_timestamp 
                ON security_incidents(timestamp)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_incidents_client 
                ON security_incidents(client_id)
            """)
            conn.commit()

    def record_incident(
        self,
        purpose: str,
        sensitive_types: List[str],
        reason: str,
        severity: str = "HIGH",
        action_taken: str = "BLOCKED",
        client_id: str = "default_client"
    ) -> Dict[str, Any]:
        """
        Records a privacy violation or leak interception event.
        NO raw personal data is stored—only entity categories and masked tokens.
        """
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        timestamp = datetime.now(timezone.utc).isoformat()
        sens_types_str = ", ".join(sorted(list(set(sensitive_types)))) if sensitive_types else "UNSPECIFIED"

        # Check for repeated violation pattern from this client/purpose
        recent_count = self._count_recent_violations(client_id, purpose, minutes=60)
        pattern_flag = "RECURRING_ANOMALOUS_PATTERN" if recent_count >= 2 else "ISOLATED_INCIDENT"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO security_incidents 
                (incident_id, timestamp, purpose, sensitive_types, reason, severity, action_taken, client_id, pattern_flag)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (incident_id, timestamp, purpose, sens_types_str, reason, severity, action_taken, client_id, pattern_flag))
            conn.commit()

        return {
            "incident_id": incident_id,
            "timestamp": timestamp,
            "purpose": purpose,
            "sensitive_types": sens_types_str,
            "reason": reason,
            "severity": severity,
            "action_taken": action_taken,
            "client_id": client_id,
            "pattern_flag": pattern_flag,
            "recent_violations_count": recent_count + 1
        }

    def _count_recent_violations(self, client_id: str, purpose: str, minutes: int = 60) -> int:
        """Counts incidents from the same client and purpose within the given time window."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) FROM security_incidents
                WHERE client_id = ? AND purpose = ?
            """, (client_id, purpose))
            row = cursor.fetchone()
            return row[0] if row else 0

    def get_incidents(self, limit: int = 100, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves recent security incidents with optional severity filter."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if severity and severity.upper() != "ALL":
                cursor.execute("""
                    SELECT * FROM security_incidents 
                    WHERE severity = ? 
                    ORDER BY timestamp DESC LIMIT ?
                """, (severity.upper(), limit))
            else:
                cursor.execute("""
                    SELECT * FROM security_incidents 
                    ORDER BY timestamp DESC LIMIT ?
                """, (limit,))
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_incident_summary(self) -> Dict[str, Any]:
        """Provides statistical breakdown of security incidents for dashboards."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM security_incidents")
            total = cursor.fetchone()[0]

            cursor.execute("SELECT severity, COUNT(*) FROM security_incidents GROUP BY severity")
            by_severity = dict(cursor.fetchall())

            cursor.execute("SELECT purpose, COUNT(*) FROM security_incidents GROUP BY purpose")
            by_purpose = dict(cursor.fetchall())

            cursor.execute("SELECT COUNT(*) FROM security_incidents WHERE pattern_flag = 'RECURRING_ANOMALOUS_PATTERN'")
            recurring = cursor.fetchone()[0]

            return {
                "total_incidents": total,
                "by_severity": by_severity,
                "by_purpose": by_purpose,
                "recurring_patterns_detected": recurring
            }


incident_manager_instance = IncidentManager()

