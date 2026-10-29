# Data Privacy & Compliance Control Plane

An enterprise-grade control plane for PII governance over tabular datasets:
**discover** what personal data you hold, **classify** it with confidence
scores, **mask or tokenize** it per policy, **prove consent** for each use,
**answer data-subject requests** (access / erasure) with an auditable trail,
**enforce retention**, and **log everything** in a tamper-evident,
hash-chained audit log.

All code is original. All data is synthetic (`example.com` addresses,
`555` phone numbers, never-issued `900`-area SSNs, public card test
numbers). No real customer data, no employer data, no proprietary designs.

## The enterprise problem

Privacy regulation (GDPR/CCPA-style access, erasure, consent, and
retention duties) usually lands as a pile of one-off scripts: a scanner
here, a redaction job there, a spreadsheet tracking DSARs. That fails in
exactly the ways auditors care about — nobody can answer, for one subject,
*what do we hold, under what consent, where did it propagate, and what
did we delete, when?* This project answers those four questions from one
coherent model: a dataset store, a consent ledger, an erasure service that
leaves tombstones, retention rules with legal-hold overrides, and a
hash-chained log over all of it.

## What it does

| Subsystem | Module | Highlights |
|---|---|---|
| PII discovery | `detectors.py` | Regex patterns (email, phone, SSN, Luhn-checked cards, IP, DOB-by-field-name) + field-name dictionary detector. Findings never carry full secrets (12-char truncated samples). |
| Classification | `classification.py` | Column-level verdict: category, confidence, sensitivity, suggested masking action, match rate. Pattern + dictionary agreement boosts confidence (capped at 0.98); ties break toward the more sensitive category. |
| Masking / tokenization | `masking.py` | Keep / partial / redact / deterministic HMAC token (in-memory vault, join-preserving, reversible only by vault holders) / salted hash. Policies derive from classifications with per-field overrides. |
| Consent ledger | `consent.py` | Purpose-scoped, field-scoped grants; withdrawal timestamps history instead of deleting it; re-grant supersedes; expiry enforced. `is_allowed()` is the single choke point downstream code asks. |
| DSAR handling | `dsar.py` | Access export across all datasets; erasure removes live records, leaves per-record tombstones (SHA-256 fingerprint, no PII), and reports downstream propagation per dataset. |
| Retention | `retention.py` | Per-dataset windows with delete / anonymize / archive actions. Legal holds always win and are reported explicitly (`held=True`), never silently skipped. |
| Audit log | `audit.py` | Hash-chained entries (`prev_hash` + entry hash); `verify()` replays the chain and names the first broken index. Tamper-evident; see the doc for the production anchor upgrade. |
| API (optional) | `api.py` | FastAPI service over the same objects. Import is guarded — without FastAPI installed, `app is None` and the library/CLI still work. |
| CLI | `cli.py` | `scan`, `mask`, `dsar`, `retention`, `demo` — CSV in, JSON out. |

## How to run it

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt        # core needs nothing; FastAPI optional

# Full pipeline over synthetic data (fastest tour of every subsystem)
PYTHONPATH=src python -m privacy_platform.cli demo

# Classify a CSV file
PYTHONPATH=src python -m privacy_platform.cli scan --input examples/sample_dataset.csv

# Mask it per classification, overriding SSN handling
PYTHONPATH=src python -m privacy_platform.cli mask --input examples/sample_dataset.csv \
    --policy ssn:tokenize,email:partial

# Data-subject request: access export, then erasure
PYTHONPATH=src python -m privacy_platform.cli dsar --input examples/sample_dataset.csv \
    --subject cust-001 --action access
PYTHONPATH=src python -m privacy_platform.cli dsar --input examples/sample_dataset.csv \
    --subject cust-001 --action erase

# Retention: report overdue records, then enforce
PYTHONPATH=src python -m privacy_platform.cli retention --input examples/sample_dataset.csv \
    --days 365 --as-of 2026-10-29
PYTHONPATH=src python -m privacy_platform.cli retention --input examples/sample_dataset.csv \
    --days 365 --as-of 2026-10-29 --enforce

# API (requires fastapi + uvicorn)
uvicorn privacy_platform.api:app --reload
```

## Tests

```bash
PYTHONPATH=src python -m pytest tests/ -q
```

The FastAPI suite auto-skips when FastAPI/httpx are not installed, so the
suite passes on a bare system Python too.

## Key design decisions and trade-offs

1. **Confidence, not certainty.** A regex hit is evidence, not proof, so
   pattern confidence tops out below 1.0 and only the Luhn check lifts a
   card candidate to high confidence. A long digit string that fails Luhn
   is *not* claimed as a card — false positives in a compliance report
   are worse than a missed column, because they trigger masking of
   legitimate business keys.
2. **Classification errs toward protection.** Ties break to the more
   sensitive category, and dictionary agreement only ever raises
   confidence. Under-classification is the expensive failure mode.
3. **Deterministic tokens preserve joins — deliberately, with a warning.**
   Same input yields the same token across datasets, so tokenized data
   stays joinable. The cost is frequency-analysis exposure on
   low-cardinality fields, which is why the vault is in-memory only and
   vault access belongs in the audit log.
4. **Erasure leaves tombstones, not nothing.** Deleting without a trace
   makes re-ingestion and audit impossible. A tombstone holds a
   fingerprint of the erased record — enough to prove *what* was erased
   and to reject its re-ingestion, without retaining any personal data.
5. **Propagation is reported, not pretended.** Downstream notification
   is listed as `propagation_requested` per system. Claiming delivery
   without acknowledgements would be a compliance lie; the report shape
   already carries the status field an outbox/acknowledgement upgrade
   needs.
6. **Legal holds beat retention, loudly.** A held record appears in the
   expiry report with `held=True` and is never actioned. Silent skips are
   how holds get violated.
7. **Tamper-evident, not tamper-proof.** A hash chain detects edits but a
   log holder could rewrite it wholesale. The production upgrade is an
   external anchor (periodic root hash to append-only storage); the chain
   already yields the root hash that anchor publishes.

## What it demonstrates

End-to-end ownership of a regulated-data problem: detection with
calibrated confidence, policy-driven de-identification, consent as a
queryable ledger, DSAR workflows with propagation reporting, retention
with legal-hold semantics, and tamper-evident auditing — the pieces a
Director-level data-platform interview probes when it asks how you would
actually run privacy engineering, not just name the regulations.

## Layout

```
src/privacy_platform/   detectors, classification, masking, consent,
                        dsar, retention, audit, cli, api
tests/                  pytest suites per subsystem (+ API, auto-skip)
docs/architecture.md    component diagram + data flows + threat notes
docs/github-actions-ci.yml  CI definition (activate by moving to
                        .github/workflows/ci.yml — see note in file)
examples/sample_dataset.csv  synthetic customers (fictitious data only)
```
