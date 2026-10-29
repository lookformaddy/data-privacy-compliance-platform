"""Command-line interface: scan / mask / dsar / retention / demo.

All commands read CSV (``--input``) and print JSON, so they compose with
jq and with pipeline steps. The ``demo`` command runs the full control
plane end-to-end over built-in synthetic data — the fastest way to see
every subsystem working together.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import date
from pathlib import Path

from privacy_platform.audit import AuditLog
from privacy_platform.classification import ColumnClassifier
from privacy_platform.consent import ConsentLedger
from privacy_platform.dsar import DataStore, DSARService
from privacy_platform.masking import MaskingAction, MaskingEngine
from privacy_platform.models import RetentionAction, RetentionRule
from privacy_platform.retention import RetentionEngine

SYNTHETIC_CUSTOMERS = [
    {
        "subject_id": "cust-001",
        "full_name": "Alex Rivera",
        "email": "alex.rivera@example.com",
        "phone": "415-555-0132",
        "ssn": "900-80-1234",
        "credit_card": "4111-1111-1111-1111",
        "created_at": "2023-01-15",
    },
    {
        "subject_id": "cust-002",
        "full_name": "Priya Nair",
        "email": "priya.nair@example.com",
        "phone": "415-555-0178",
        "ssn": "900-80-5678",
        "credit_card": "5555-5555-5555-4444",
        "created_at": "2025-06-01",
    },
]


def _read_csv(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _print_json(payload: object) -> None:
    print(json.dumps(payload, indent=2, default=str))


def _parse_policies(spec: str) -> dict[str, MaskingAction]:
    policies: dict[str, MaskingAction] = {}
    if not spec:
        return policies
    for pair in spec.split(","):
        field, _, action = pair.partition(":")
        policies[field.strip()] = MaskingAction(action.strip())
    return policies


def cmd_scan(args: argparse.Namespace) -> int:
    records = _read_csv(args.input)
    results = ColumnClassifier().classify_dataset(records)
    _print_json(
        [
            {
                "field": r.field,
                "category": r.category.value,
                "confidence": r.confidence,
                "sensitivity": r.sensitivity.value,
                "suggested_action": r.suggested_action.value,
                "match_rate": r.match_rate,
            }
            for r in results
            if r.confidence >= args.min_confidence
        ]
    )
    return 0


def cmd_mask(args: argparse.Namespace) -> int:
    records = _read_csv(args.input)
    classifications = ColumnClassifier().classify_dataset(records)
    engine = MaskingEngine.from_classifications(
        classifications, overrides=_parse_policies(args.policy)
    )
    _print_json(engine.mask_dataset(records))
    return 0


def cmd_dsar(args: argparse.Namespace) -> int:
    store = DataStore()
    store.add_dataset("customers", _read_csv(args.input))
    service = DSARService(store, downstream_map={"customers": ["analytics_warehouse", "crm"]})
    if args.action == "access":
        _print_json(service.access(args.subject))
    else:
        report = service.erase(args.subject)
        _print_json(
            {
                "subject_id": report.subject_id,
                "datasets_erased": report.datasets_erased,
                "tombstones": len(report.tombstones),
                "propagation": [
                    {"dataset": p.dataset, "downstream_system": p.downstream_system, "status": p.status}
                    for p in report.propagation
                ],
                "erasure_verified": store.verify_erasure(args.subject),
            }
        )
    return 0


def cmd_retention(args: argparse.Namespace) -> int:
    datasets = {"customers": _read_csv(args.input)}
    rule = RetentionRule(
        dataset="customers",
        retention_days=args.days,
        action=RetentionAction(args.action),
    )
    engine = RetentionEngine([rule], pii_fields=["email", "phone", "ssn", "credit_card"])
    as_of = date.fromisoformat(args.as_of)
    if args.enforce:
        _print_json(engine.apply(datasets, as_of))
    else:
        _print_json(
            [
                {
                    "dataset": f.dataset,
                    "subject_id": f.subject_id,
                    "due_date": str(f.due_date),
                    "overdue": f.overdue,
                    "action": f.action.value,
                    "held": f.held,
                }
                for f in engine.report(datasets, as_of)
            ]
        )
    return 0


def run_demo() -> dict:
    """Full pipeline over synthetic data; returns a JSON-able summary."""
    classifier = ColumnClassifier()
    classifications = classifier.classify_dataset(SYNTHETIC_CUSTOMERS)
    engine = MaskingEngine.from_classifications(classifications)
    masked = engine.mask_dataset(SYNTHETIC_CUSTOMERS)

    ledger = ConsentLedger()
    ledger.grant("cust-001", "marketing", fields=("email",))
    ledger.withdraw("cust-001", "marketing")

    store = DataStore()
    store.add_dataset("customers", SYNTHETIC_CUSTOMERS)
    service = DSARService(store, downstream_map={"customers": ["analytics_warehouse"]})
    access = service.access("cust-002")
    report = service.erase("cust-001")

    audit = AuditLog()
    audit.append("privacy-officer", "dsar_access", "cust-002")
    audit.append("privacy-officer", "dsar_erasure", "cust-001",
                 {"tombstones": len(report.tombstones)})
    intact, _ = audit.verify()

    retention = RetentionEngine(
        [RetentionRule("customers", 365, RetentionAction.ANONYMIZE)],
        pii_fields=["email", "phone"],
    )
    expiry = retention.report(store.datasets, date(2026, 10, 29))
    return {
        "classifications": [
            {"field": c.field, "category": c.category.value, "confidence": c.confidence,
             "sensitivity": c.sensitivity.value, "suggested_action": c.suggested_action.value}
            for c in classifications
        ],
        "masked_sample": masked[0],
        "consent_marketing_cust001_allowed": ledger.is_allowed("cust-001", "marketing", "email"),
        "access_cust002_records": sum(len(v) for v in access.values()),
        "erasure": {"datasets_erased": report.datasets_erased,
                    "propagation": [p.downstream_system for p in report.propagation]},
        "audit_chain_intact": intact,
        "audit_root_hash": audit.root_hash[:16] + "…",
        "retention_overdue": sum(1 for f in expiry if f.overdue),
    }


def cmd_demo(_args: argparse.Namespace) -> int:
    _print_json(run_demo())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="privacy-platform", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="Classify columns of a CSV file")
    p.add_argument("--input", required=True)
    p.add_argument("--min-confidence", type=float, default=0.0)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("mask", help="Mask a CSV file per classification + overrides")
    p.add_argument("--input", required=True)
    p.add_argument("--policy", default="", help="e.g. email:partial,ssn:tokenize")
    p.set_defaults(func=cmd_mask)

    p = sub.add_parser("dsar", help="Access export or erasure for one subject")
    p.add_argument("--input", required=True)
    p.add_argument("--subject", required=True)
    p.add_argument("--action", choices=["access", "erase"], required=True)
    p.set_defaults(func=cmd_dsar)

    p = sub.add_parser("retention", help="Retention expiry report (or --enforce)")
    p.add_argument("--input", required=True)
    p.add_argument("--days", type=int, default=365)
    p.add_argument("--action", choices=["delete", "anonymize", "archive"], default="anonymize")
    p.add_argument("--as-of", default="2026-10-29")
    p.add_argument("--enforce", action="store_true")
    p.set_defaults(func=cmd_retention)

    p = sub.add_parser("demo", help="End-to-end demo over synthetic data")
    p.set_defaults(func=cmd_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
