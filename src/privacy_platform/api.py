"""Optional FastAPI service wrapping the control plane.

The import is guarded: importing this module without FastAPI installed
leaves ``app = None`` instead of crashing, so the core library and the
CLI stay usable on a bare system Python. Install ``fastapi`` + ``uvicorn``
(see requirements.txt) and run::

    uvicorn privacy_platform.api:app --reload
"""

from __future__ import annotations

try:
    from fastapi import FastAPI
except ImportError:  # pragma: no cover - exercised by the skip in test_api.py
    FastAPI = None  # type: ignore

from privacy_platform.audit import AuditLog
from privacy_platform.classification import ColumnClassifier
from privacy_platform.consent import ConsentLedger
from privacy_platform.dsar import DataStore, DSARService
from privacy_platform.masking import MaskingEngine
from privacy_platform.models import RetentionAction, RetentionRule
from privacy_platform.retention import RetentionEngine

if FastAPI is not None:
    app = FastAPI(title="Privacy & Compliance Control Plane")
    _classifier = ColumnClassifier()
    _ledger = ConsentLedger()
    _store = DataStore()
    _dsar = DSARService(_store)
    _audit = AuditLog()

    @app.post("/scan")
    def scan(body: dict) -> dict:
        records = body.get("records", [])
        return {
            "columns": [
                {
                    "field": c.field,
                    "category": c.category.value,
                    "confidence": c.confidence,
                    "sensitivity": c.sensitivity.value,
                    "suggested_action": c.suggested_action.value,
                }
                for c in _classifier.classify_dataset(records)
            ]
        }

    @app.post("/mask")
    def mask(body: dict) -> dict:
        records = body.get("records", [])
        engine = MaskingEngine.from_classifications(_classifier.classify_dataset(records))
        return {"records": engine.mask_dataset(records)}

    @app.post("/consent/grant")
    def consent_grant(body: dict) -> dict:
        record = _ledger.grant(
            body["subject_id"], body["purpose"], fields=tuple(body.get("fields", ()))
        )
        _audit.append("api", "consent_granted", body["subject_id"], {"purpose": body["purpose"]})
        return {"status": record.status.value, "purpose": record.purpose}

    @app.post("/consent/check")
    def consent_check(body: dict) -> dict:
        return {
            "allowed": _ledger.is_allowed(body["subject_id"], body["purpose"], body["field"])
        }

    @app.post("/dsar/access")
    def dsar_access(body: dict) -> dict:
        return _dsar.access(body["subject_id"])

    @app.post("/dsar/erasure")
    def dsar_erasure(body: dict) -> dict:
        report = _dsar.erase(body["subject_id"])
        _audit.append("api", "dsar_erasure", body["subject_id"],
                      {"datasets": report.datasets_erased})
        return {
            "datasets_erased": report.datasets_erased,
            "tombstones": len(report.tombstones),
            "verified": _store.verify_erasure(body["subject_id"]),
        }

    @app.get("/retention/report")
    def retention_report(as_of: str = "2026-10-29") -> dict:
        from datetime import date

        engine = RetentionEngine(
            [RetentionRule("customers", 365, RetentionAction.ANONYMIZE)]
        )
        findings = engine.report(_store.datasets, date.fromisoformat(as_of))
        return {
            "overdue": sum(1 for f in findings if f.overdue),
            "total": len(findings),
        }

    @app.get("/audit/verify")
    def audit_verify() -> dict:
        intact, broken = _audit.verify()
        return {"intact": intact, "broken_index": broken, "root_hash": _audit.root_hash}
else:
    app = None
