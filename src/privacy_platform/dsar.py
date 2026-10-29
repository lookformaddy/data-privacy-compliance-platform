"""Data-subject requests (DSAR): access export and erasure with tombstones.

Erasure model
-------------
Erasing a subject removes their live records from every dataset and leaves
a :class:`~privacy_platform.models.Tombstone` per record: dataset, subject,
timestamp, reason, and a SHA-256 fingerprint of the canonical pre-erasure
record. The fingerprint lets an auditor prove *which* record was erased
without retaining any of its personal data, and it doubles as a
re-ingestion guard — a pipeline can reject a record whose fingerprint
matches a tombstone.

Propagation is reported, not pretended: downstream systems are declared
per dataset, and the report lists each one as ``propagation_requested``.
A real deployment would replace that step with outbox events / webhooks
and track acknowledgements; the report shape already carries the status
field that upgrade needs.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime

from privacy_platform.models import (
    DSARStatus,
    ErasureReport,
    PropagationEntry,
    Tombstone,
)


def _fingerprint(record: dict) -> str:
    canonical = json.dumps(record, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class DataStore:
    """In-memory datasets; records carry a ``subject_id`` field by default."""

    def __init__(self, subject_field: str = "subject_id") -> None:
        self.subject_field = subject_field
        self.datasets: dict[str, list[dict]] = {}
        self.tombstones: list[Tombstone] = []

    def add_dataset(self, name: str, records: list[dict]) -> None:
        self.datasets[name] = copy.deepcopy(records)

    def records_for(self, subject_id: str) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        for name, records in self.datasets.items():
            matches = [copy.deepcopy(r) for r in records if r.get(self.subject_field) == subject_id]
            if matches:
                out[name] = matches
        return out

    def verify_erasure(self, subject_id: str) -> bool:
        return not self.records_for(subject_id)


class DSARService:
    def __init__(
        self,
        store: DataStore,
        downstream_map: dict[str, list[str]] | None = None,
    ) -> None:
        self.store = store
        self.downstream_map = downstream_map or {}

    def access(self, subject_id: str) -> dict[str, list[dict]]:
        """Access export: every live record held about the subject."""
        return self.store.records_for(subject_id)

    def erase(self, subject_id: str, reason: str = "data_subject_erasure_request") -> ErasureReport:
        erased: dict[str, int] = {}
        tombstones: list[Tombstone] = []
        propagation: list[PropagationEntry] = []
        for name, records in self.store.datasets.items():
            kept: list[dict] = []
            count = 0
            for record in records:
                if record.get(self.store.subject_field) == subject_id:
                    tombstone = Tombstone(
                        dataset=name,
                        subject_id=subject_id,
                        erased_at=datetime.utcnow(),
                        reason=reason,
                        record_fingerprint=_fingerprint(record),
                    )
                    tombstones.append(tombstone)
                    self.store.tombstones.append(tombstone)
                    count += 1
                else:
                    kept.append(record)
            self.store.datasets[name] = kept
            if count:
                erased[name] = count
                for downstream in self.downstream_map.get(name, []):
                    propagation.append(
                        PropagationEntry(
                            dataset=name,
                            downstream_system=downstream,
                            records_affected=count,
                        )
                    )
        return ErasureReport(
            subject_id=subject_id,
            datasets_erased=erased,
            tombstones=tombstones,
            propagation=propagation,
            status=DSARStatus.COMPLETED,
        )
