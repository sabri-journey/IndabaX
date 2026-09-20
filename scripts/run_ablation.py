#!/usr/bin/env python3
"""F6 -- run the full published scenario library under every ablation
configuration and emit a single comparison table.

For each configuration in CONFIGS: launch this defense as a real subprocess
with the matching environment variables set (ablation.py reads them),
wait for /healthz, run `sentinel eval <split> --defense-url ... --json`
against it from the starter kit, collect the metrics, then tear the server
down and move to the next configuration. This is an honest end-to-end
comparison through the real wire contract -- not a mocked substitute.

Usage (from this repo's root):
    python scripts/run_ablation.py
    python scripts/run_ablation.py --split validation
    python scripts/run_ablation.py --starter-kit /path/to/Sentinel_Starter_Kit
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

CONFIGS: dict[str, dict[str, str]] = {
    "full": {},
    "no_normalisation": {"SENTINEL_NO_NORMALISATION": "1"},
    "no_bayes": {"SENTINEL_NO_BAYES": "1"},
    "no_provenance": {"SENTINEL_NO_PROVENANCE": "1"},
    "no_state_machine": {"SENTINEL_NO_STATE_MACHINE": "1"},
    "no_secret_detector": {"SENTINEL_NO_SECRET_DETECTOR": "1"},
    "rules_only": {"SENTINEL_RULES_ONLY": "1"},
}

ALL_TOGGLE_KEYS = (
    "SENTINEL_NO_NORMALISATION",
    "SENTINEL_NO_BAYES",
    "SENTINEL_NO_PROVENANCE",
    "SENTINEL_NO_STATE_MACHINE",
    "SENTINEL_NO_SECRET_DETECTOR",
    "SENTINEL_RULES_ONLY",
)

METRIC_KEYS = ["btu", "asr", "cvr", "fbr", "uer", "tui", "dfi", "brier", "ece"]


def _wait_healthy(url: str, timeout_s: float = 15.0) -> None:
    deadline = time.time() + timeout_s
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"{url}/healthz", timeout=1)
            return
        except (urllib.error.URLError, ConnectionError, OSError) as exc:
            last_error = exc
            time.sleep(0.3)
    raise RuntimeError(f"defense service at {url} did not become healthy in {timeout_s}s: {last_error}")


def run_one(overrides: dict[str, str], starter_kit: Path, port: int, split: str) -> dict:
    env = dict(os.environ)
    for key in ALL_TOGGLE_KEYS:
        env.pop(key, None)
    env.update(overrides)
    env["PYTHONPATH"] = str(REPO_ROOT / "src")

    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "defense.adapter:app", "--port", str(port)],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_healthy(f"http://127.0.0.1:{port}")
        result = subprocess.run(
            ["uv", "run", "sentinel", "eval", split, "--defense-url", f"http://127.0.0.1:{port}", "--json"],
            cwd=starter_kit,
            capture_output=True,
            text=True,
            check=True,
        )
        report = json.loads(result.stdout)
        return report["metrics"]
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--starter-kit", type=Path, default=Path.home() / "Sentinel_Starter_Kit")
    parser.add_argument("--split", default="public", choices=["public", "validation"])
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "results" / "ablation.md")
    args = parser.parse_args()

    if not args.starter_kit.is_dir():
        raise SystemExit(f"starter kit not found at {args.starter_kit} -- pass --starter-kit")

    rows: dict[str, dict] = {}
    for name, overrides in CONFIGS.items():
        print(f"=== {name} ({overrides or 'no overrides'}) ===", file=sys.stderr)
        rows[name] = run_one(overrides, args.starter_kit, args.port, args.split)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Ablation study ({args.split} split, `--model mock`)",
        "",
        "Each row is a full `sentinel eval` run of this defense with one component",
        "disabled via `src/defense/ablation.py`'s environment-variable toggles.",
        "`full` is every component enabled (build steps 2-6 as shipped).",
        "",
        "| config | " + " | ".join(METRIC_KEYS) + " |",
        "| --- | " + " | ".join("---" for _ in METRIC_KEYS) + " |",
    ]
    for name, metrics in rows.items():
        cells = []
        for key in METRIC_KEYS:
            value = metrics.get(key)
            cells.append("n/a" if value is None else f"{value:.3f}")
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    args.output.write_text("\n".join(lines) + "\n")
    print(f"wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
