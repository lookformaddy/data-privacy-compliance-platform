from datetime import date

from privacy_platform.audit import AuditLog
from privacy_platform.models import RetentionAction, RetentionRule
from privacy_platform.retention import RetentionEngine


def _datasets():
    return {
        "customers": [
            {"subject_id": "old", "email": "old@example.com", "created_at": "2023-01-15"},
            {"subject_id": "held", "email": "held@example.com", "created_at": "2023-01-15"},
            {"subject_id": "fresh", "email": "fresh@example.com", "created_at": "2026-06-01"},
        ]
    }


def test_retention_report_flags_overdue_and_held_subjects():
    engine = RetentionEngine([
        RetentionRule("customers", 365, RetentionAction.DELETE,
                      legal_hold_subjects=frozenset({"held"})),
    ])
    findings = {(f.subject_id): f for f in engine.report(_datasets(), date(2026, 10, 29))}
    assert findings["old"].overdue and not findings["old"].held
    assert findings["held"].overdue and findings["held"].held
    assert not findings["fresh"].overdue
    assert findings["old"].due_date == date(2024, 1, 15)


def test_retention_apply_deletes_overdue_but_never_held_records():
    datasets = _datasets()
    engine = RetentionEngine([
        RetentionRule("customers", 365, RetentionAction.DELETE,
                      legal_hold_subjects=frozenset({"held"})),
    ])
    summary = engine.apply(datasets, date(2026, 10, 29))
    assert summary["deleted"] == 1
    assert summary["held_skipped"] == 1
    remaining = {r["subject_id"] for r in datasets["customers"]}
    assert remaining == {"held", "fresh"}


def test_retention_anonymize_redacts_pii_fields_in_place():
    datasets = _datasets()
    engine = RetentionEngine(
        [RetentionRule("customers", 365, RetentionAction.ANONYMIZE)],
        pii_fields=["email"],
    )
    summary = engine.apply(datasets, date(2026, 10, 29))
    assert summary["anonymized"] == 2
    by_subject = {r["subject_id"]: r for r in datasets["customers"]}
    assert by_subject["old"]["email"] == "[REDACTED]"
    assert by_subject["fresh"]["email"] == "fresh@example.com"


def test_audit_chain_verifies_and_detects_tampering():
    log = AuditLog()
    log.append("officer", "dsar_erasure", "cust-001")
    log.append("officer", "dsar_access", "cust-002")
    intact, broken = log.verify()
    assert intact and broken is None

    log.entries[0].details = {"tampered": True}  # rewrite history
    intact, broken = log.verify()
    assert not intact and broken == 0


def test_audit_chain_links_entries_and_exposes_root_hash():
    log = AuditLog()
    first = log.append("api", "scan", "cust-001")
    second = log.append("api", "mask", "cust-001")
    assert second.prev_hash == first.entry_hash
    assert log.root_hash == second.entry_hash
    assert log.to_jsonl().count("\n") == 1  # two entries, one separator
