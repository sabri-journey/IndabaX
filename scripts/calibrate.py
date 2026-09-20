#!/usr/bin/env python3
"""F5 -- calibration is a deliverable, not a by-product.

Reads a `sentinel eval ... --json` report and produces a 10-equal-width-bin
reliability table plus a hand-drawn SVG reliability diagram (no plotting
library dependency -- this repo stays pure-Python/offline). Recomputes
Brier/ECE directly from the per-decision (risk_score, legitimate) pairs so
the numbers are traceable to individual decisions, not just the harness's
own aggregate.

Usage:
    uv run sentinel eval public --defense-url http://127.0.0.1:8080 --json > results/eval_public_full.json
    python scripts/calibrate.py results/eval_public_full.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
N_BINS = 10


def load_decisions(report_path: Path) -> list[tuple[float, bool]]:
    """(risk_score, illegitimate) pairs -- illegitimate = not legitimate,
    matching scoring.md's Brier/ECE label convention (label 1 = illegitimate)."""
    report = json.loads(report_path.read_text())
    pairs: list[tuple[float, bool]] = []
    for outcome in report["outcomes"]:
        for decision in outcome["decisions"]:
            pairs.append((float(decision["risk_score"]), not decision["legitimate"]))
    return pairs


def bin_stats(pairs: list[tuple[float, bool]], n_bins: int = N_BINS) -> list[dict]:
    bins = [{"lo": i / n_bins, "hi": (i + 1) / n_bins, "risks": [], "labels": []} for i in range(n_bins)]
    for risk, label in pairs:
        index = min(int(risk * n_bins), n_bins - 1)
        bins[index]["risks"].append(risk)
        bins[index]["labels"].append(label)
    stats = []
    for b in bins:
        count = len(b["risks"])
        mean_risk = sum(b["risks"]) / count if count else None
        observed = sum(b["labels"]) / count if count else None
        stats.append({"lo": b["lo"], "hi": b["hi"], "count": count, "mean_risk": mean_risk, "observed": observed})
    return stats


def brier_and_ece(pairs: list[tuple[float, bool]], stats: list[dict]) -> tuple[float, float]:
    n = len(pairs)
    brier = sum((risk - (1.0 if label else 0.0)) ** 2 for risk, label in pairs) / n
    ece = sum((s["count"] / n) * abs(s["observed"] - s["mean_risk"]) for s in stats if s["count"])
    return brier, ece


def render_markdown(stats: list[dict], brier: float, ece: float, n: int) -> str:
    lines = [
        f"# Calibration ({n} decisions)",
        "",
        f"Brier score: **{brier:.4f}** (lower is better; label 1 = illegitimate action)",
        f"ECE (10 equal-width bins): **{ece:.4f}** (lower is better)",
        "",
        "| bin | count | mean predicted risk | observed illegitimate fraction |",
        "| --- | --- | --- | --- |",
    ]
    for s in stats:
        mean_risk = "n/a" if s["mean_risk"] is None else f"{s['mean_risk']:.3f}"
        observed = "n/a" if s["observed"] is None else f"{s['observed']:.3f}"
        lines.append(f"| [{s['lo']:.1f}, {s['hi']:.1f}) | {s['count']} | {mean_risk} | {observed} |")
    return "\n".join(lines) + "\n"


def render_svg(stats: list[dict], width: int = 420, height: int = 420, pad: int = 40) -> str:
    plot = width - 2 * pad
    points = [(s["mean_risk"], s["observed"]) for s in stats if s["count"]]

    def to_x(v: float) -> float:
        return pad + v * plot

    def to_y(v: float) -> float:
        return height - pad - v * plot

    circles = "".join(
        f'<circle cx="{to_x(x):.1f}" cy="{to_y(y):.1f}" r="4" fill="#2563eb" />' for x, y in points
    )
    polyline = " ".join(f"{to_x(x):.1f},{to_y(y):.1f}" for x, y in points)
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <rect width="{width}" height="{height}" fill="white" />
  <line x1="{pad}" y1="{height - pad}" x2="{width - pad}" y2="{height - pad}" stroke="#333" />
  <line x1="{pad}" y1="{pad}" x2="{pad}" y2="{height - pad}" stroke="#333" />
  <line x1="{to_x(0):.1f}" y1="{to_y(0):.1f}" x2="{to_x(1):.1f}" y2="{to_y(1):.1f}" stroke="#999" stroke-dasharray="4,4" />
  <polyline points="{polyline}" fill="none" stroke="#2563eb" stroke-width="2" />
  {circles}
  <text x="{width / 2}" y="{height - 8}" text-anchor="middle" font-size="12" font-family="sans-serif">mean predicted risk</text>
  <text x="12" y="{height / 2}" text-anchor="middle" font-size="12" font-family="sans-serif" transform="rotate(-90 12 {height / 2})">observed illegitimate fraction</text>
  <text x="{pad}" y="20" font-size="12" font-family="sans-serif" fill="#666">dashed line = perfect calibration</text>
</svg>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="sentinel eval ... --json output file")
    parser.add_argument("--output-prefix", type=Path, default=None, help="default: results/<report stem>_calibration")
    args = parser.parse_args()

    pairs = load_decisions(args.report)
    stats = bin_stats(pairs)
    brier, ece = brier_and_ece(pairs, stats)

    prefix = args.output_prefix or (REPO_ROOT / "results" / f"{args.report.stem}_calibration")
    prefix.parent.mkdir(parents=True, exist_ok=True)
    prefix.with_suffix(".md").write_text(render_markdown(stats, brier, ece, len(pairs)))
    prefix.with_suffix(".svg").write_text(render_svg(stats))

    print(f"decisions: {len(pairs)}")
    print(f"brier: {brier:.4f}  ece: {ece:.4f}")
    print(f"wrote {prefix.with_suffix('.md')}")
    print(f"wrote {prefix.with_suffix('.svg')}")


if __name__ == "__main__":
    main()
