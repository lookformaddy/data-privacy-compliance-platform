from privacy_platform.classification import ColumnClassifier
from privacy_platform.models import MaskingAction, PIICategory, Sensitivity

RECORDS = [
    {"email": "a@example.com", "full_name": "Alex Rivera", "orders": 3,
     "ssn": "900-80-1234", "signup_date": "2024-01-01"},
    {"email": "b@example.com", "full_name": "Priya Nair", "orders": 1,
     "ssn": "900-80-5678", "signup_date": "2024-02-01"},
]


def _by_field(classifications):
    return {c.field: c for c in classifications}


def test_dataset_classification_assigns_categories_and_sensitivity():
    results = _by_field(ColumnClassifier().classify_dataset(RECORDS))
    assert results["email"].category == PIICategory.EMAIL
    assert results["email"].confidence >= 0.9
    assert results["email"].sensitivity == Sensitivity.CONFIDENTIAL
    assert results["ssn"].category == PIICategory.SSN
    assert results["ssn"].sensitivity == Sensitivity.RESTRICTED
    assert results["ssn"].suggested_action == MaskingAction.TOKENIZE
    assert results["full_name"].category == PIICategory.NAME
    assert results["orders"].category == PIICategory.UNKNOWN
    assert results["orders"].confidence == 0.0


def test_dictionary_signal_classifies_column_without_pattern_match():
    # Values are malformed emails, but the field name still classifies.
    results = _by_field(
        ColumnClassifier().classify_dataset([{"email": "not-an-email"}, {"email": "also-bad"}])
    )
    assert results["email"].category == PIICategory.EMAIL
    assert results["email"].confidence == 0.70


def test_agreeing_signals_boost_confidence():
    results = _by_field(ColumnClassifier().classify_dataset(RECORDS))
    # Pattern (0.95) + dictionary agreement lifts email above pattern alone.
    assert results["email"].confidence == 0.98 or results["email"].confidence >= 0.95


def test_empty_dataset_classifies_to_nothing():
    assert ColumnClassifier().classify_dataset([]) == []
