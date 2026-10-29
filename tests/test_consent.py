from datetime import datetime, timedelta

from privacy_platform.consent import ConsentLedger


def test_grant_allows_scoped_field_and_denies_others():
    ledger = ConsentLedger()
    ledger.grant("cust-001", "marketing", fields=("email",))
    assert ledger.is_allowed("cust-001", "marketing", "email")
    assert not ledger.is_allowed("cust-001", "marketing", "phone")
    assert not ledger.is_allowed("cust-001", "analytics", "email")


def test_withdrawal_denies_but_preserves_history():
    ledger = ConsentLedger()
    ledger.grant("cust-001", "marketing")
    assert ledger.is_allowed("cust-001", "marketing", "email")
    withdrawn = ledger.withdraw("cust-001", "marketing")
    assert withdrawn is not None and withdrawn.withdrawn_at is not None
    assert not ledger.is_allowed("cust-001", "marketing", "email")
    assert len(ledger.history("cust-001")) == 1  # history is append-only


def test_regrant_after_withdrawal_restores_access():
    ledger = ConsentLedger()
    ledger.grant("cust-001", "marketing")
    ledger.withdraw("cust-001", "marketing")
    ledger.grant("cust-001", "marketing")
    assert ledger.is_allowed("cust-001", "marketing", "email")
    assert len(ledger.history("cust-001")) == 2


def test_expired_grant_denies():
    ledger = ConsentLedger()
    past = datetime.utcnow() - timedelta(days=10)
    ledger.grant("cust-001", "marketing", expires_in_days=5, granted_at=past)
    assert not ledger.is_allowed("cust-001", "marketing", "email")


def test_withdraw_with_no_active_grant_returns_none():
    assert ConsentLedger().withdraw("nobody", "marketing") is None
