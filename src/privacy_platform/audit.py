"""Hash-chained audit log: tamper-evident compliance evidence.

Each entry commits to the previous entry's hash, so deleting or editing
any historical entry breaks every hash after it. ``verify()`` replays the
chain and reports the first broken index (or None when intact).

This is tamper-*evident*, not tamper-*proof*: a holder of the log file
could rewrite the whole chain from scratch. Production hardening is an
external anchor (periodic root hash published to append-only storage or
a transparency log) — the chain shape here already yields the root hash
that anchor would publish.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime

GENESIS_HASH = "0" * 64


@dataclass
class AuditEntry:
    index: int
    timestamp: str
    actor: str
    action: str
    subject_id: str
    details: dict
    prev_hash: str
    entry_hash: str


def _entry_hash(
    index: int,
    timestamp: str,
    actor: str,
    action: str,
    subject_id: str,
    details: dict,
    prev_hash: str,
) -> str:
    payload = json.dumps(
        {
            "index": index,
            "timestamp": timestamp,
            "actor": actor,
            "action": action,
            "subject_id": subject_id,
            "details": details,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


class AuditLog:
    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def append(
        self, actor: str, action: str, subject_id: str = "", details: dict | None = None
    ) -> AuditEntry:
        prev_hash = self.entries[-1].entry_hash if self.entries else GENESIS_HASH
        entry = AuditEntry(
            index=len(self.entries),
            timestamp=datetime.utcnow().isoformat() + "Z",
            actor=actor,
            action=action,
            subject_id=subject_id,
            details=details or {},
            prev_hash=prev_hash,
            entry_hash="",
        )
        entry.entry_hash = _entry_hash(
            entry.index,
            entry.timestamp,
            entry.actor,
            entry.action,
            entry.subject_id,
            entry.details,
            entry.prev_hash,
        )
        self.entries.append(entry)
        return entry

    def verify(self) -> tuple[bool, int | None]:
        """Return (is_intact, first_broken_index or None)."""
        prev_hash = GENESIS_HASH
        for entry in self.entries:
            if entry.prev_hash != prev_hash:
                return False, entry.index
            expected = _entry_hash(
                entry.index,
                entry.timestamp,
                entry.actor,
                entry.action,
                entry.subject_id,
                entry.details,
                entry.prev_hash,
            )
            if entry.entry_hash != expected:
                return False, entry.index
            prev_hash = entry.entry_hash
        return True, None

    @property
    def root_hash(self) -> str:
        return self.entries[-1].entry_hash if self.entries else GENESIS_HASH

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(asdict(e), sort_keys=True, default=str) for e in self.entries)
