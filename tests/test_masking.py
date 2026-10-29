from privacy_platform.masking import (
    MaskingEngine,
    TokenVault,
    partial_mask,
    salted_hash,
)
from privacy_platform.models import MaskingAction


def test_partial_mask_keeps_email_domain_and_hides_local_part():
    assert partial_mask("alex.rivera@example.com") == "a***@example.com"
    assert partial_mask("415-555-0132") == "41********32"


def test_tokenization_is_deterministic_and_reversible_via_vault():
    vault = TokenVault(key="test-key")
    token_a = vault.tokenize("900-80-1234")
    assert vault.tokenize("900-80-1234") == token_a  # same input -> same token
    assert vault.detokenize(token_a) == "900-80-1234"
    assert vault.detokenize("TOK_unknown") is None


def test_hash_is_one_way_and_salted():
    digest = salted_hash("a@example.com", "k1")
    assert digest != salted_hash("a@example.com", "k2")
    assert len(digest) == 64


def test_engine_applies_per_field_policies_and_keeps_unlisted_fields():
    engine = MaskingEngine(
        policies={"email": MaskingAction.PARTIAL, "ssn": MaskingAction.REDACT},
    )
    masked = engine.mask_record(
        {"email": "a@example.com", "ssn": "123-45-6789", "orders": 3}
    )
    assert masked["email"] == "a***@example.com"
    assert masked["ssn"] == "[REDACTED]"
    assert masked["orders"] == 3  # unlisted fields pass through untouched


def test_engine_from_classifications_uses_suggested_actions():
    from privacy_platform.classification import ColumnClassifier
    from privacy_platform.cli import SYNTHETIC_CUSTOMERS

    engine = MaskingEngine.from_classifications(
        ColumnClassifier().classify_dataset(SYNTHETIC_CUSTOMERS)
    )
    masked = engine.mask_dataset(SYNTHETIC_CUSTOMERS)[0]
    assert masked["email"] == "a***@example.com"
    assert masked["ssn"].startswith("TOK_")  # RESTRICTED -> tokenize
    assert masked["subject_id"] == "cust-001"  # identifiers are not PII fields here
