"""End-to-end: the CLI demo pipeline must complete with all subsystems green."""

from privacy_platform.cli import main, run_demo


def test_demo_pipeline_summary():
    summary = run_demo()
    assert summary["classifications"]  # discovery ran
    assert summary["masked_sample"]["email"] == "a***@example.com"
    assert summary["consent_marketing_cust001_allowed"] is False  # withdrawn
    assert summary["access_cust002_records"] == 1
    assert summary["erasure"]["datasets_erased"] == {"customers": 1}
    assert summary["erasure"]["propagation"] == ["analytics_warehouse"]
    assert summary["audit_chain_intact"] is True


def test_cli_demo_command_exits_zero(capsys):
    assert main(["demo"]) == 0
    assert "audit_chain_intact" in capsys.readouterr().out
