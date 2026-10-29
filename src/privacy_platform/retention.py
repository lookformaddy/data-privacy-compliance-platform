"""Retention policies: expiry reporting and enforcement.

A rule names a dataset, a retention window in days, and what happens at
expiry (delete / anonymize / archive). Records are dated by a configurable
date field (default ``created_at``, ISO ``YYYY-MM-DD``). Subjects on a
legal hold are reported but never actioned — a hold always wins over
expiry, and the report says so explicitly (``held=True``) instead of
silently skipping the record.
"""

from __future__ import annotations

from datetime import date, timedelta

from privacy_platform.models import ExpiryFinding, RetentionAction, RetentionRule

REDACTED = "[REDACTED]"


def _parse_date(raw: object) -> date | None:
    if raw is None:
        return None
    try:
        return date.fromisoformat(str(raw)[:10])
    except ValueError:
        return None


class RetentionEngine:
    def __init__(self, rules: list[RetentionRule], pii_fields: list[str] | None = None) -> None:
        self.rules = {rule.dataset: rule for rule in rules}
        self.pii_fields = pii_fields or []

    def report(self, datasets: dict[str, list[dict]], as_of: date) -> list[ExpiryFinding]:
        findings: list[ExpiryFinding] = []
        for name, records in datasets.items():
            rule = self.rules.get(name)
            if rule is None:
                continue
            for record in records:
                subject_id = str(record.get("subject_id", ""))
                created = _parse_date(record.get(rule.date_field))
                due = created + timedelta(days=rule.retention_days) if created else None
                findings.append(
                    ExpiryFinding(
                        dataset=name,
                        subject_id=subject_id,
                        created_at=created,
                        due_date=due,
                        overdue=bool(due and due <= as_of),
                        action=rule.action,
                        held=subject_id in rule.legal_hold_subjects,
                    )
                )
        return findings

    def apply(self, datasets: dict[str, list[dict]], as_of: date) -> dict[str, int]:
        """Enforce overdue, non-held findings. Returns counts per action taken."""
        summary: dict[str, int] = {"deleted": 0, "anonymized": 0, "archived": 0, "held_skipped": 0}
        findings = self.report(datasets, as_of)
        overdue_keys = {
            (f.dataset, f.subject_id)
            for f in findings
            if f.overdue and not f.held
        }
        held_keys = {(f.dataset, f.subject_id) for f in findings if f.overdue and f.held}
        summary["held_skipped"] = len(held_keys)
        for name, records in datasets.items():
            rule = self.rules.get(name)
            if rule is None:
                continue
            kept: list[dict] = []
            for record in records:
                key = (name, str(record.get("subject_id", "")))
                if key not in overdue_keys:
                    kept.append(record)
                    continue
                if rule.action is RetentionAction.DELETE:
                    summary["deleted"] += 1
                elif rule.action is RetentionAction.ANONYMIZE:
                    for pii_field in self.pii_fields:
                        if pii_field in record:
                            record[pii_field] = REDACTED
                    summary["anonymized"] += 1
                    kept.append(record)
                elif rule.action is RetentionAction.ARCHIVE:
                    record["_archived"] = True
                    summary["archived"] += 1
                    kept.append(record)
            datasets[name] = kept
        return summary
