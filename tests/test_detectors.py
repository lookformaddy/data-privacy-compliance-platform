from privacy_platform.detectors import (
    DictionaryDetector,
    PatternDetector,
    luhn_ok,
)
from privacy_platform.models import PIICategory


def test_luhn_accepts_known_test_cards_and_rejects_typos():
    assert luhn_ok("4111111111111111")
    assert luhn_ok("5555555555554444")
    assert not luhn_ok("4111111111111112")
    assert not luhn_ok("12345")


def test_pattern_detector_finds_email_phone_ssn_and_card():
    detector = PatternDetector()
    assert detector.scan_value("x", "alex.rivera@example.com")[0].category == PIICategory.EMAIL
    assert detector.scan_value("x", "415-555-0132")[0].category == PIICategory.PHONE
    assert detector.scan_value("x", "123-45-6789")[0].category == PIICategory.SSN
    card = detector.scan_value("x", "4111-1111-1111-1111")
    assert card and card[0].category == PIICategory.CREDIT_CARD


def test_long_digit_string_without_luhn_pass_is_not_claimed_as_card():
    detector = PatternDetector()
    assert detector.scan_value("order_ref", "4111-1111-1111-1112") == []


def test_non_pii_values_produce_no_findings():
    detector = PatternDetector()
    assert detector.scan_value("x", "hello world") == []
    assert detector.scan_value("x", "") == []
    assert detector.scan_value("x", "42") == []


def test_dictionary_detector_maps_field_names():
    detector = DictionaryDetector()
    assert detector.category_for_field("customer_email") == PIICategory.EMAIL
    assert detector.category_for_field("ssn") == PIICategory.SSN
    assert detector.category_for_field("date_of_birth") == PIICategory.DATE_OF_BIRTH
    assert detector.category_for_field("order_total") is None


def test_findings_never_carry_full_secrets():
    detector = PatternDetector()
    finding = detector.scan_value("x", "alex.rivera@example.com")[0]
    assert len(finding.matched_value) <= 13  # 12 chars + ellipsis
    assert finding.matched_value != "alex.rivera@example.com"
