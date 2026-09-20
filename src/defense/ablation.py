"""Ablation toggles (F6): every major component disableable by environment
variable, read once at process start-up.

`scripts/run_ablation.py` launches this service once per configuration
(a real subprocess, real HTTP calls) and runs it against the actual
published scenario library via `sentinel eval` -- an honest end-to-end
comparison, not a mocked substitute for one.

  SENTINEL_NO_NORMALISATION=1    stage 0 becomes a no-op (raw text, untouched)
  SENTINEL_NO_BAYES=1            stage 1 returns a flat, uninformative posterior
  SENTINEL_NO_PROVENANCE=1       provenance_condition / destination_provenance /
                                  instruction_mirrors_untrusted / sensitive_sink
                                  rule kinds are skipped (everything that
                                  depends on provenance.py)
  SENTINEL_NO_STATE_MACHINE=1    prerequisite / consequential_approval /
                                  forced_confirmation rule kinds are skipped
                                  (everything that depends on state_machine.py)
  SENTINEL_NO_SECRET_DETECTOR=1  secret_sink rule kind is skipped (the one
                                  rule kind that depends on secrets.py alone)
  SENTINEL_RULES_ONLY=1          shorthand: stage 1 off AND the rewrite
                                  catalogue off -- deterministic stage-2
                                  rules only, every hard finding is a flat
                                  BLOCK
"""

from __future__ import annotations

import os


def _flag(name: str) -> bool:
    return os.environ.get(name, "") not in ("", "0", "false", "False")


def normalisation_enabled() -> bool:
    return not _flag("SENTINEL_NO_NORMALISATION")


def bayes_enabled() -> bool:
    return not (_flag("SENTINEL_NO_BAYES") or _flag("SENTINEL_RULES_ONLY"))


def rewrites_enabled() -> bool:
    return not _flag("SENTINEL_RULES_ONLY")


def provenance_rules_enabled() -> bool:
    return not _flag("SENTINEL_NO_PROVENANCE")


def state_machine_rules_enabled() -> bool:
    return not _flag("SENTINEL_NO_STATE_MACHINE")


def secret_detector_rules_enabled() -> bool:
    return not _flag("SENTINEL_NO_SECRET_DETECTOR")
