"""REASON_CODES.md is a *closed* taxonomy (F7) -- this test keeps it honest:
every reason code the system can actually emit must appear in the
documented list, so the file can't silently drift out of date."""

from __future__ import annotations

from pathlib import Path

from defense.stage1_bayes import cached_likelihoods
from defense.stage2_policy import cached_default_rules

REPO_ROOT = Path(__file__).resolve().parents[1]

# Emitted directly by stage3_decide.py / adapter.py, not loaded from YAML.
HARDCODED_CODES = {"POLICY_CLEAN", "SEQ_RISK_ACCUMULATION", "CONFIRMATION_REQUESTED", "DEGRADED_FAIL_CLOSED"}


def test_every_reason_code_is_documented() -> None:
    doc = (REPO_ROOT / "REASON_CODES.md").read_text()

    rule_codes = {rule.reason_code for rule in cached_default_rules()}
    signal_ids = {spec.id for spec in cached_likelihoods()}

    missing = [code for code in sorted(rule_codes | signal_ids | HARDCODED_CODES) if code not in doc]
    assert not missing, f"reason codes missing from REASON_CODES.md: {missing}"
