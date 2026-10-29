"""Masking & tokenization engine.

Actions
-------
* ``keep`` — value passes through unchanged.
* ``partial`` — first/last characters visible, middle replaced. Emails keep
  the domain (``j***@example.com``) because the domain is rarely sensitive
  and keeps records joinable for analytics.
* ``redact`` — replaced with ``[REDACTED]``.
* ``tokenize`` — replaced with a deterministic ``TOK_<hmac>`` surrogate.
  The mapping lives ONLY in the in-memory :class:`TokenVault`: tokens are
  consistent across datasets (same input -> same token, so joins still
  work) and reversible only by a holder of the vault. The vault is never
  serialized by this module — persisting it needs its own access control.
* ``hash`` — one-way salted SHA-256; for analytics keys, not reversible.

Trade-off (documented, not hidden): deterministic tokens preserve joins
but are vulnerable to frequency analysis on low-cardinality fields, which
is why RESTRICTED defaults to tokenize while CONFIDENTIAL defaults to
partial masking, and why vault access must be audited (see audit log).
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod

from privacy_platform.models import MaskingAction

REDACTED = "[REDACTED]"


class TokenVault:
    """In-memory token <-> original mapping. Never persisted by this class."""

    def __init__(self, key: str = "dev-only-change-me") -> None:
        self._key = key.encode()
        self._tokens: dict[str, str] = {}

    def tokenize(self, value: str) -> str:
        digest = hmac_mod.new(self._key, value.encode(), hashlib.sha256).hexdigest()[:20]
        token = f"TOK_{digest}"
        self._tokens[token] = value
        return token

    def detokenize(self, token: str) -> str | None:
        return self._tokens.get(token)

    def __len__(self) -> int:
        return len(self._tokens)


def partial_mask(value: str) -> str:
    if "@" in value:  # email-style: keep first char + domain
        local, domain = value.split("@", 1)
        return f"{local[:1]}***@{domain}"
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * max(1, len(value) - 4)}{value[-2:]}"


def salted_hash(value: str, key: str) -> str:
    return hashlib.sha256(f"{key}:{value}".encode()).hexdigest()


class MaskingEngine:
    def __init__(
        self,
        policies: dict[str, MaskingAction] | None = None,
        default_action: MaskingAction = MaskingAction.KEEP,
        vault: TokenVault | None = None,
        hash_key: str = "dev-only-change-me",
    ) -> None:
        self.policies = policies or {}
        self.default_action = default_action
        self.vault = vault or TokenVault(key=hash_key)
        self.hash_key = hash_key

    def mask_value(self, value: object, action: MaskingAction) -> object:
        if value is None or action is MaskingAction.KEEP:
            return value
        text = str(value)
        if action is MaskingAction.REDACT:
            return REDACTED
        if action is MaskingAction.PARTIAL:
            return partial_mask(text)
        if action is MaskingAction.TOKENIZE:
            return self.vault.tokenize(text)
        if action is MaskingAction.HASH:
            return salted_hash(text, self.hash_key)
        raise ValueError(f"unknown masking action: {action}")

    def mask_record(self, record: dict) -> dict:
        return {
            field: self.mask_value(value, self.policies.get(field, self.default_action))
            for field, value in record.items()
        }

    def mask_dataset(self, records: list[dict]) -> list[dict]:
        return [self.mask_record(record) for record in records]

    @classmethod
    def from_classifications(cls, classifications, overrides: dict[str, MaskingAction] | None = None) -> "MaskingEngine":
        policies = {c.field: c.suggested_action for c in classifications}
        if overrides:
            policies.update(overrides)
        return cls(policies=policies)
