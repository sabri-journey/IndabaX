"""F5 -- calibration script's math, checked against a hand-computed synthetic
example (scripts/ isn't part of the defense package, so this imports it
directly by path)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "calibrate.py"
spec = importlib.util.spec_from_file_location("calibrate", SCRIPT_PATH)
calibrate = importlib.util.module_from_spec(spec)
sys.modules["calibrate"] = calibrate
spec.loader.exec_module(calibrate)  # type: ignore[union-attr]


def test_bin_stats_and_brier_on_a_perfectly_calibrated_toy_example() -> None:
    # 10 decisions at risk 0.9, 9 of them actually illegitimate: observed
    # fraction 0.9 exactly matches predicted risk 0.9 -- ECE should be ~0.
    pairs = [(0.9, True)] * 9 + [(0.9, False)] * 1
    stats = calibrate.bin_stats(pairs)
    bin_9 = next(s for s in stats if s["lo"] == 0.9)
    assert bin_9["count"] == 10
    assert abs(bin_9["mean_risk"] - 0.9) < 1e-9
    assert abs(bin_9["observed"] - 0.9) < 1e-9

    brier, ece = calibrate.brier_and_ece(pairs, stats)
    assert ece < 1e-9  # perfectly calibrated bin
    # Brier: 9 * (0.9-1)^2 + 1 * (0.9-0)^2 = 9*0.01 + 1*0.81 = 0.9, /10 = 0.09
    assert abs(brier - 0.09) < 1e-9


def test_miscalibrated_example_has_nonzero_ece() -> None:
    # Predicted 0.9 for everything, but none of them are actually
    # illegitimate -- badly overconfident.
    pairs = [(0.95, False)] * 5
    stats = calibrate.bin_stats(pairs)
    _, ece = calibrate.brier_and_ece(pairs, stats)
    assert ece > 0.9  # observed 0 vs predicted ~0.95


def test_empty_bins_are_excluded_from_ece() -> None:
    pairs = [(0.0, False), (1.0, True)]  # exactly correct predictions
    stats = calibrate.bin_stats(pairs)
    occupied = [s for s in stats if s["count"]]
    assert len(occupied) == 2
    brier, ece = calibrate.brier_and_ece(pairs, stats)
    assert brier == 0.0
    assert ece == 0.0
