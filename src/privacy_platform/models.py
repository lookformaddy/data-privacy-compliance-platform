"""Shared data model for the privacy & compliance control plane.

Everything here is plain typed dataclasses/enums — no framework dependency —
so the core logic is testable without FastAPI and portable to a service,
a batch job, or a library.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum


class PIICategory(str, Enum):
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    NAME = "name"
    ADDRESS = "address"
    DATE_OF_BIRTH = "date_of_birth"
    IP_ADDRESS = "ip_address"
    ACCOUNT_ID = "account_id"
    UNKNOWN = "unknown"


class Sensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class MaskingAction(str, Enum):
    KEEP = "keep"
    PARTIAL = "partial"
    REDACT = "redact"
    TOKENIZE = "tokenize"
    HASH = "hash"


class ConsentStatus(str, Enum):
    GRANTED = "granted"
    WITHDRAWN = "withdrawn"
    EXPIRED = "expired"


class DSARType(str, Enum):
    ACCESS = "access"
    ERASURE = "erasure"


class DSARStatus(str, Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"  # e.g. some records held back by a legal hold


class RetentionAction(str, Enum):
    DELETE = "delete"
    ANONYMIZE = "anonymize"
    ARCHIVE = "archive"


# Sensitivity ladder: higher-sensitivity categories get stronger defaults.
SENSITIVITY_BY_CATEGORY: dict[PIICategory, Sensitivity] = {
    PIICategory.SSN: Sensitivity.RESTRICTED,
    PIICategory.CREDIT_CARD: Sensitivity.RESTRICTED,
    PIICategory.EMAIL: Sensitivity.CONFIDENTIAL,
    PIICategory.PHONE: Sensitivity.CONFIDENTIAL,
    PIICategory.DATE_OF_BIRTH: Sensitivity.CONFIDENTIAL,
    PIICategory.ADDRESS: Sensitivity.CONFIDENTIAL,
    PIICategory.NAME: Sensitivity.INTERNAL,
    PIICategory.IP_ADDRESS: Sensitivity.INTERNAL,
    PIICategory.ACCOUNT_ID: Sensitivity.INTERNAL,
    PIICategory.UNKNOWN: Sensitivity.PUBLIC,
}

DEFAULT_ACTION_BY_SENSITIVITY: dict[Sensitivity, MaskingAction] = {
    Sensitivity.RESTRICTED: MaskingAction.TOKENIZE,
    Sensitivity.CONFIDENTIAL: MaskingAction.PARTIAL,
    Sensitivity.INTERNAL: MaskingAction.KEEP,
    Sensitivity.PUBLIC: MaskingAction.KEEP,
}


@dataclass(frozen=True)
class Finding:
    """One detector hit on a single value."""

    field: str
    category: PIICategory
    confidence: float  # 0.0 - 1.0
    detector: str
    matched_value: str = ""  # truncated sample, never a full secret


@dataclass
class ColumnClassification:
    field: str
    category: PIICategory
    confidence: float
    sensitivity: Sensitivity
    suggested_action: MaskingAction
    match_rate: float  # fraction of non-empty values that matched
    detectors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class FieldPolicy:
    field: str
    action: MaskingAction
    reason: str = ""


@dataclass
class ConsentRecord:
    subject_id: str
    purpose: str
    fields: tuple[str, ...] = ()
    granted_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime | None = None
    withdrawn_at: datetime | None = None

    @property
    def status(self) -> ConsentStatus:
        if self.withdrawn_at is not None:
            return ConsentStatus.WITHDRAWN
        if self.expires_at is not None and datetime.utcnow() >= self.expires_at:
            return ConsentStatus.EXPIRED
        return ConsentStatus.GRANTED


@dataclass
class Tombstone:
    """What remains after erasure: proof a record existed, no personal data."""

    dataset: str
    subject_id: str
    erased_at: datetime
    reason: str
    record_fingerprint: str  # sha256 of the canonical pre-erasure record


@dataclass
class PropagationEntry:
    dataset: str
    downstream_system: str
    records_affected: int
    status: str = "propagation_requested"


@dataclass
class ErasureReport:
    subject_id: str
    datasets_erased: dict[str, int]
    tombstones: list[Tombstone]
    propagation: list[PropagationEntry]
    status: DSARStatus = DSARStatus.COMPLETED


@dataclass
class RetentionRule:
    dataset: str
    retention_days: int
    action: RetentionAction
    date_field: str = "created_at"
    legal_hold_subjects: frozenset[str] = frozenset()


@dataclass
class ExpiryFinding:
    dataset: str
    subject_id: str
    created_at: date | None
    due_date: date | None
    overdue: bool
    action: RetentionAction
    held: bool
