# Architecture

## Components

```
CSV / JSON records
      │
      ▼
┌─────────────────────┐
│ ColumnClassifier    │  PatternDetector + DictionaryDetector
│  → ColumnClassification (category, confidence, sensitivity,
│     suggested_action, match_rate)
└────────┬────────────┘
         │ policies (per-field overrides allowed)
         ▼
┌─────────────────────┐
│ MaskingEngine       │  keep / partial / redact / tokenize (TokenVault)
│                     │  / salted hash
└────────┬────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────┐
│ DataStore  ── datasets keyed by name, records carry       │
│              subject_id; tombstones kept separately       │
│   ├─ DSARService: access export · erasure → tombstones    │
│   │   + propagation report per declared downstream        │
│   ├─ RetentionEngine: rules → expiry report → enforce    │
│   │   (delete / anonymize / archive; legal holds win)     │
│   └─ ConsentLedger: purpose+field grants, withdrawal,     │
│       expiry — is_allowed() is the single choke point     │
└────────┬──────────────────────────────────────────────────┘
         │ every mutation appends here
         ▼
┌─────────────────────┐
│ AuditLog            │  hash-chained entries, verify() replays
│                     │  the chain, root_hash = anchor value
└─────────────────────┘
         ▲
  CLI (csv → json) · FastAPI service (optional, guarded import)
```

## Data flows

1. **Discovery flow.** `scan` runs detectors over each column and emits
   one `ColumnClassification` per column. No raw values leave the
   scanner except 12-character truncated samples inside `Finding`
   objects, which are never serialized by the CLI.
2. **Masking flow.** Classifications map to default actions via
   `DEFAULT_ACTION_BY_SENSITIVITY` (RESTRICTED → tokenize,
   CONFIDENTIAL → partial, else keep); per-field overrides win.
   Tokenization is deterministic (HMAC with a vault key) so masked
   datasets remain joinable; the vault is in-memory only.
3. **DSAR flow.** `access` collects a subject's records across all
   datasets. `erase` removes them, appends one tombstone per record
   (dataset, subject, timestamp, reason, SHA-256 fingerprint of the
   canonical pre-erasure record), and emits a propagation entry per
   declared downstream system with status `propagation_requested`.
4. **Retention flow.** `report` computes due dates from each record's
   date field and flags overdue rows; `apply` executes the rule action
   only for overdue, non-held rows and counts held skips separately.
5. **Audit flow.** Every DSAR/consent/retention mutation appends an
   `AuditEntry` chaining to the previous entry's hash. `verify()`
   recomputes every hash and returns the first broken index.

## Threat / failure notes

* **Token vault theft** exposes the token↔original mapping: the vault
  must live behind the same access control as the audit log, and vault
  reads should themselves be audited (a planned extension, not yet
  implemented).
* **Chain rewrite**: the audit log detects edits but not wholesale
  rewrites. Anchor `root_hash` periodically to append-only storage.
* **Re-ingestion after erasure**: pipelines must check new records
  against tombstone fingerprints before loading; the fingerprint makes
  this a lookup, not a policy document.
* **Scope limits (honest)**: this is an in-memory reference
  implementation. A production deployment needs durable storage for the
  store, ledger, vault, and log; authenticated API access; and real
  downstream propagation (outbox + acknowledgements) replacing the
  `propagation_requested` placeholder.
