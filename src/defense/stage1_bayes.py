"""Stage 1 -- sequential Bayesian monitor over session risk.

Maintains a posterior P(session_is_compromised) per session
(session_store.py, keyed by `DecisionContext.session_key` -- never the raw
run_id, see guard.py), updated with a naive-Bayes log-odds update every
step: apply a decay factor toward the prior FIRST (so an old, resolved
suspicion doesn't poison a long benign session), then multiply in a
likelihood ratio for every evidence signal observed this step.

Likelihood ratios and their justifications live in config/likelihoods.yaml,
thresholds in config/thresholds.yaml -- not hardcoded here, so the report
can cite them and an ablation can disable the whole stage or individual
signals (build step 7).

Genuinely complementary to stage 2, not redundant with it:
`history_digest.least_trusted_seen` resets every turn (verified against the
starter kit's agent/reference.py: `self._turn_provenance` is reset per
turn), so a slow-burn pattern spanning multiple turns is invisible to any
single request's snapshot. This stage's session-local posterior persists
across the whole run, which is what actually gives multi-step / adaptive /
long-horizon (difficulty 3-5) coverage that a purely per-action review
cannot have.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from defense.context import DecisionContext
from defense.provenance import TRUST_RANK
from defense.session_store import SessionState
from defense.stage2_policy import PolicyVerdict

DEFAULT_LIKELIHOODS_PATH = Path(__file__).resolve().parents[2] / "config" / "likelihoods.yaml"
DEFAULT_THRESHOLDS_PATH = Path(__file__).resolve().parents[2] / "config" / "thresholds.yaml"

STRUCTURAL_SIGNAL_ID = "UNTRUSTED_CONTENT_OBSERVED"
SESSION_KEY = "bayes"


@dataclass(frozen=True)
class SignalSpec:
    id: str
    reason_codes: tuple[str, ...]
    likelihood_ratio: float
    justification: str = ""


@dataclass(frozen=True)
class BayesConfig:
    prior_p_compromised: float = 0.1
    decay_factor: float = 0.85
    escalate_risk_threshold: float = 0.75
    escalate_confidence_threshold: float = 0.5
    hysteresis_consecutive_steps: int = 2
    bayes_escalation_requires_consequential_or_sink: bool = True
    evidence_scale: float = 6.0
    strong_signal_likelihood_ratio: float = 3.0


@dataclass(frozen=True)
class BayesResult:
    risk: float
    confidence: float
    reason_codes: tuple[str, ...] = ()
    hysteresis_met: bool = False


def load_likelihoods(path: Path = DEFAULT_LIKELIHOODS_PATH) -> list[SignalSpec]:
    raw = yaml.safe_load(path.read_text())
    return [
        SignalSpec(
            id=entry["id"],
            reason_codes=tuple(entry.get("reason_codes", [])),
            likelihood_ratio=float(entry["likelihood_ratio"]),
            justification=entry.get("justification", ""),
        )
        for entry in raw.get("signals", [])
    ]


def load_thresholds(path: Path = DEFAULT_THRESHOLDS_PATH) -> BayesConfig:
    raw: dict[str, Any] = yaml.safe_load(path.read_text()).get("bayes", {})
    defaults = BayesConfig()
    return BayesConfig(
        prior_p_compromised=float(raw.get("prior_p_compromised", defaults.prior_p_compromised)),
        decay_factor=float(raw.get("decay_factor", defaults.decay_factor)),
        escalate_risk_threshold=float(raw.get("escalate_risk_threshold", defaults.escalate_risk_threshold)),
        escalate_confidence_threshold=float(
            raw.get("escalate_confidence_threshold", defaults.escalate_confidence_threshold)
        ),
        hysteresis_consecutive_steps=int(
            raw.get("hysteresis_consecutive_steps", defaults.hysteresis_consecutive_steps)
        ),
        bayes_escalation_requires_consequential_or_sink=bool(
            raw.get(
                "bayes_escalation_requires_consequential_or_sink",
                defaults.bayes_escalation_requires_consequential_or_sink,
            )
        ),
        evidence_scale=float(raw.get("evidence_scale", defaults.evidence_scale)),
        strong_signal_likelihood_ratio=float(
            raw.get("strong_signal_likelihood_ratio", defaults.strong_signal_likelihood_ratio)
        ),
    )


_LIKELIHOODS: list[SignalSpec] | None = None
_THRESHOLDS: BayesConfig | None = None


def cached_likelihoods() -> list[SignalSpec]:
    global _LIKELIHOODS
    if _LIKELIHOODS is None:
        _LIKELIHOODS = load_likelihoods()
    return _LIKELIHOODS


def cached_thresholds() -> BayesConfig:
    global _THRESHOLDS
    if _THRESHOLDS is None:
        _THRESHOLDS = load_thresholds()
    return _THRESHOLDS


def _p_to_log_odds(p: float) -> float:
    p = min(max(p, 1e-6), 1 - 1e-6)
    return math.log(p / (1 - p))


def _log_odds_to_p(log_odds: float) -> float:
    return 1.0 / (1.0 + math.exp(-log_odds))


def _observed_untrusted_content(ctx: DecisionContext) -> bool:
    return any(
        TRUST_RANK[record.provenance.trust_level] >= TRUST_RANK["untrusted_internal"] for record in ctx.provenance
    )


def _active_signals(ctx: DecisionContext, policy: PolicyVerdict, likelihoods: list[SignalSpec]) -> list[SignalSpec]:
    reason_codes = {f.reason_code for f in policy.findings} | set(ctx.normalisation_signals)
    active: list[SignalSpec] = []
    for spec in likelihoods:
        if spec.id == STRUCTURAL_SIGNAL_ID:
            if _observed_untrusted_content(ctx):
                active.append(spec)
            continue
        if reason_codes & set(spec.reason_codes):
            active.append(spec)
    return active


def update(
    ctx: DecisionContext,
    session: SessionState,
    policy: PolicyVerdict,
    config: BayesConfig | None = None,
    likelihoods: list[SignalSpec] | None = None,
) -> BayesResult:
    config = config or cached_thresholds()
    likelihoods = likelihoods if likelihoods is not None else cached_likelihoods()

    prior_log_odds = _p_to_log_odds(config.prior_p_compromised)
    state = session.extra.setdefault(SESSION_KEY, {"log_odds": prior_log_odds, "evidence_weight": 0.0, "streak": 0})

    # Decay toward the prior BEFORE adding this step's evidence.
    state["log_odds"] = prior_log_odds + config.decay_factor * (state["log_odds"] - prior_log_odds)
    state["evidence_weight"] *= config.decay_factor

    fired = _active_signals(ctx, policy, likelihoods)
    for spec in fired:
        log_lr = math.log(spec.likelihood_ratio)
        state["log_odds"] += log_lr
        state["evidence_weight"] += abs(log_lr)

    risk = _log_odds_to_p(state["log_odds"])
    confidence = 1.0 - math.exp(-state["evidence_weight"] / config.evidence_scale)

    # Hysteresis counts consecutive steps of *fresh, active* evidence, not
    # "the decayed posterior number happens to still sit above threshold
    # from evidence several steps ago." Found as a real false positive
    # during build step 7's ablation run: after a hard finding correctly
    # BLOCKs an attack step, the very next -- entirely clean -- legitimate
    # action inherited enough residual log-odds from that one step to read
    # as "still crossed" and got swept into SEQ_RISK_ACCUMULATION. Requiring
    # a strong signal (not just the deliberately-weak
    # UNTRUSTED_CONTENT_OBSERVED/MISSING_CONFIRMATION signals) to have fired
    # on THIS step is what "sustained" is supposed to mean.
    strong_fired_this_step = any(spec.likelihood_ratio >= config.strong_signal_likelihood_ratio for spec in fired)
    crossed = (
        risk >= config.escalate_risk_threshold
        and confidence >= config.escalate_confidence_threshold
        and strong_fired_this_step
    )
    state["streak"] = state["streak"] + 1 if crossed else 0
    hysteresis_met = state["streak"] >= config.hysteresis_consecutive_steps

    return BayesResult(
        risk=round(risk, 4),
        confidence=round(confidence, 4),
        reason_codes=tuple(sorted(spec.id for spec in fired)),
        hysteresis_met=hysteresis_met,
    )
