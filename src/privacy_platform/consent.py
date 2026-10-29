"""Consent ledger: purpose-scoped, append-only grants with withdrawal.

Semantics
---------
* A grant is scoped to a *purpose* (e.g. ``marketing``) and optionally to a
  set of fields. An empty field set means "all fields for that purpose".
* Withdrawal never deletes history: it timestamps the latest active grant.
  A later re-grant supersedes the withdrawal — the ledger keeps both rows,
  so an auditor can reconstruct exactly what was permitted at any time.
* ``is_allowed`` answers the only question downstream code should ask:
  "may this field be used for this purpose for this subject, right now?"
"""

from __future__ import annotations

from datetime import datetime, timedelta

from privacy_platform.models import ConsentRecord, ConsentStatus


class ConsentLedger:
    def __init__(self) -> None:
        self._records: list[ConsentRecord] = []

    def grant(
        self,
        subject_id: str,
        purpose: str,
        fields: tuple[str, ...] | list[str] = (),
        expires_in_days: int | None = None,
        granted_at: datetime | None = None,
    ) -> ConsentRecord:
        now = granted_at or datetime.utcnow()
        expires_at = now + timedelta(days=expires_in_days) if expires_in_days else None
        record = ConsentRecord(
            subject_id=subject_id,
            purpose=purpose,
            fields=tuple(fields),
            granted_at=now,
            expires_at=expires_at,
        )
        self._records.append(record)
        return record

    def withdraw(
        self, subject_id: str, purpose: str, withdrawn_at: datetime | None = None
    ) -> ConsentRecord | None:
        """Withdraw the latest still-active grant for (subject, purpose)."""
        for record in reversed(self._records):
            if (
                record.subject_id == subject_id
                and record.purpose == purpose
                and record.status is ConsentStatus.GRANTED
            ):
                record.withdrawn_at = withdrawn_at or datetime.utcnow()
                return record
        return None

    def latest(self, subject_id: str, purpose: str) -> ConsentRecord | None:
        for record in reversed(self._records):
            if record.subject_id == subject_id and record.purpose == purpose:
                return record
        return None

    def is_allowed(self, subject_id: str, purpose: str, field: str) -> bool:
        record = self.latest(subject_id, purpose)
        if record is None or record.status is not ConsentStatus.GRANTED:
            return False
        if record.fields and field not in record.fields:
            return False
        return True

    def history(self, subject_id: str) -> list[ConsentRecord]:
        return [r for r in self._records if r.subject_id == subject_id]

    def __len__(self) -> int:
        return len(self._records)
