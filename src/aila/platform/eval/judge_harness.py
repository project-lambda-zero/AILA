"""Judge-reliability harness for the claim verifier (issue #152).

The claim verifier (:class:`aila.platform.agents.claim_verifier.ClaimVerifierAgentBase`)
publishes a ``{verdict, confidence}`` pair on every canonical outcome via
``payload["verifier_report"]``. The verdict prompt in
``system_claim_verifier_verdict.md`` anchors the confidence scale at
0.5 / 0.7 / 0.9 bands, but nothing in the pipeline measures whether the
anchor is actually calibrated, and nothing stress-tests the two judge-bias
classes that reliably wreck LLM-as-judge scoring: order sensitivity and
verbosity sensitivity.

This module supplies three things a CI or nightly job can wire onto the
live verifier output:

1. **Calibration metrics** -- pure functions over ``(predicted_confidence,
   correct_bool)`` lists. :func:`brier_score` and :func:`wilson_interval`
   join :func:`aila.platform.eval.metrics.ece` (Expected Calibration Error)
   so a single seed set produces ECE + Brier + Wilson-interval-width for
   the operator dashboard. All three are dependency-free and unit-testable
   without any LLM.

2. **Label-independent bias stress tests** --
   :func:`stress_position_bias` runs the verifier twice with the evidence
   sections permuted and reports the verdict-flip rate + confidence delta.
   :func:`stress_verbosity_bias` pads the claim with irrelevant filler and
   measures the same. Neither needs a human label; both detect an
   invariance violation the verifier prompt already implicitly promises
   (the same probes should reach the same verdict regardless of section
   order or claim-text verbosity).

3. **Seed loader + CLI** -- :func:`load_seed` parses a JSON seed file of
   ``{claim, evidence, label, provenance, ...}`` rows with strict
   provenance checking (no unlabelled placeholder rows). The bundled
   ``bootstrap_judge_seed.json`` is a small, clearly-marked bootstrap
   drawn from the codebase's recorded verifier-report fixtures; the seed
   file's ``_meta`` block cites the source paths. ``python -m
   aila.platform.eval.judge_harness --seed <path>`` is the runnable
   entrypoint that prints ECE / Brier / interval width, plus a bias-stress
   summary when the seed carries ``recorded_verdict`` + baseline / perturbed
   pairs.

The harness treats the real verifier as an opaque
``VerifierFn = async fn(*, claim, evidence) -> VerifierVerdict`` protocol so
the tests exercise the metrics + stress logic with a stub verifier and the
live CI wiring plugs in a thin adapter over
:meth:`ClaimVerifierAgentBase.run` without this module having to import the
full LLM / MCP stack.
"""
from __future__ import annotations

import argparse
import json
import math
import random
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from aila.platform.eval.metrics import calibration_curve, ece

__all__ = [
    "BOOTSTRAP_SEED_PATH",
    "BiasCase",
    "BiasSummary",
    "CalibrationSummary",
    "SeedClaim",
    "SeedLoadError",
    "VALID_LABELS",
    "VALID_VERDICTS",
    "VerifierFn",
    "VerifierVerdict",
    "brier_score",
    "load_seed",
    "main",
    "permute_evidence_sections",
    "score_calibration",
    "score_calibration_from_recorded",
    "stress_position_bias",
    "stress_verbosity_bias",
    "verbose_pad_claim",
    "wilson_interval",
]

# Bootstrap seed lives next to this module so `python -m
# aila.platform.eval.judge_harness --seed <default>` works out of the box.
BOOTSTRAP_SEED_PATH = Path(__file__).parent / "bootstrap_judge_seed.json"

# The three verdict labels the verifier prompt is allowed to emit and the
# three labels the seed loader accepts as ground truth. "inconclusive"
# rows do not enter calibration scoring (there is no truthy "correct" to
# check against a confidence) but they do enter bias-stress scoring
# because permuting evidence on a genuinely inconclusive claim should
# still yield "inconclusive" and a similar confidence.
VALID_VERDICTS = ("confirmed", "refuted", "inconclusive")
VALID_LABELS = VALID_VERDICTS

_FILLER_PARAGRAPH = (
    "Note: for context, prior investigations in this workspace have also "
    "examined unrelated subsystems and produced audit memos that were "
    "later archived. The following claim is unrelated to those artifacts "
    "and should be evaluated purely on its own probe evidence."
)


class SeedLoadError(ValueError):
    """The seed file did not parse or a row failed schema validation."""


@dataclass(frozen=True, slots=True)
class SeedClaim:
    """One judge-harness seed row.

    ``claim`` and ``evidence`` are the two strings the verifier consumes;
    ``label`` is the ground-truth verdict (from operator review of a
    resolved investigation, from expert annotation, or from a codified
    bootstrap fixture). ``recorded_verdict`` / ``recorded_confidence`` are
    optional -- when present they are the verifier's actual historical
    output on this claim, so calibration metrics can be computed from the
    seed alone without re-running the LLM verifier. ``provenance`` MUST
    cite the source of the row so an operator can trace any surprising
    metric back to real recorded data.
    """
    claim_id: str
    claim: str
    evidence: str
    label: str
    provenance: str
    recorded_verdict: str | None = None
    recorded_confidence: float | None = None


@dataclass(frozen=True, slots=True)
class VerifierVerdict:
    """The subset of ``payload['verifier_report']`` the harness reads.

    Mirrors the shape :class:`aila.platform.agents.claim_verifier.ClaimVerifierAgentBase`
    persists (verdict + numeric confidence in [0, 1]).
    """
    verdict: str
    confidence: float


class VerifierFn(Protocol):
    """Callable protocol for a claim verifier.

    Real production wiring adapts
    :meth:`ClaimVerifierAgentBase.run` behind this signature so the
    harness stays independent of the LLM / MCP stack. Test stubs
    implement the same signature without any I/O.
    """
    async def __call__(self, *, claim: str, evidence: str) -> VerifierVerdict: ...


# ---------------------------------------------------------------------------
# Pure metric functions -- dependency-free, unit-testable without an LLM.
# ---------------------------------------------------------------------------


def brier_score(
    confidences: Sequence[float],
    correct: Sequence[bool],
) -> float:
    """Mean squared error between predicted confidence and correctness.

    ``Brier = mean_i (confidence_i - correct_i)^2`` where ``correct_i`` is
    1.0 when the predicted verdict matched the ground-truth label and 0.0
    otherwise. Lower is better; a perfectly-calibrated forecaster on a
    50/50 split floors at 0.25 (irreducible), a perfect classifier at 0.0.
    """
    if len(confidences) != len(correct):
        raise ValueError("confidences and correct must be the same length")
    if not confidences:
        return 0.0
    total = 0.0
    for conf, ok in zip(confidences, correct, strict=True):
        diff = conf - (1.0 if ok else 0.0)
        total += diff * diff
    return total / len(confidences)


def wilson_interval(
    successes: int,
    n: int,
    *,
    z: float = 1.96,
) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Returns ``(lo, hi)`` clipped to ``[0, 1]``. ``z = 1.96`` is the
    two-sided 95% band. The interval WIDTH is a legitimate
    prediction-set / interval-width metric on the harness's headline
    accuracy: it shrinks as N grows and grows toward 1.0 as N -> 0, so a
    small seed size shows up as a wide interval on the operator report
    instead of a suspiciously precise-looking single number.
    """
    if n < 0:
        raise ValueError("n must be non-negative")
    if successes < 0 or successes > n:
        raise ValueError("successes must be in [0, n]")
    if n == 0:
        return (0.0, 1.0)
    phat = successes / n
    denom = 1.0 + (z * z) / n
    center = (phat + (z * z) / (2.0 * n)) / denom
    half = (z / denom) * math.sqrt((phat * (1.0 - phat) / n) + (z * z) / (4.0 * n * n))
    return (max(0.0, center - half), min(1.0, center + half))


# ---------------------------------------------------------------------------
# Seed loader.
# ---------------------------------------------------------------------------


def _validate_confidence(value: Any, *, field_name: str, row_id: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SeedLoadError(
            f"row {row_id}: {field_name} must be a number in [0, 1], got {value!r}"
        )
    conf = float(value)
    if not (0.0 <= conf <= 1.0):
        raise SeedLoadError(
            f"row {row_id}: {field_name}={conf} out of [0, 1]"
        )
    return conf


def load_seed(path: Path) -> list[SeedClaim]:
    """Parse the seed JSON file into :class:`SeedClaim` rows.

    Seed file shape (top-level object)::

        {
          "_meta": { "description": "...", "sources": ["..."] },
          "rows": [
            { "claim_id": "...", "claim": "...", "evidence": "...",
              "label": "confirmed" | "refuted" | "inconclusive",
              "provenance": "...",
              "recorded_verdict": "...",         # optional
              "recorded_confidence": 0.87        # optional, in [0, 1]
            }, ...
          ]
        }

    Every row MUST carry a non-empty ``provenance``; the loader refuses
    rows with an empty or missing provenance so the seed cannot silently
    accumulate fabricated labels.
    """
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SeedLoadError(f"could not read seed file {path}: {exc}") from exc
    try:
        raw = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise SeedLoadError(f"seed file {path} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise SeedLoadError(
            f"seed file {path} top level must be an object, got {type(raw).__name__}"
        )
    rows = raw.get("rows")
    if not isinstance(rows, list):
        raise SeedLoadError(f"seed file {path} missing 'rows' array")
    parsed: list[SeedClaim] = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            raise SeedLoadError(f"row {i} must be an object")
        rid = str(row.get("claim_id") or f"row-{i}")
        claim = row.get("claim")
        evidence = row.get("evidence")
        label = row.get("label")
        provenance = row.get("provenance")
        if not isinstance(claim, str) or not claim.strip():
            raise SeedLoadError(f"row {rid}: 'claim' must be a non-empty string")
        if not isinstance(evidence, str) or not evidence.strip():
            raise SeedLoadError(f"row {rid}: 'evidence' must be a non-empty string")
        if label not in VALID_LABELS:
            raise SeedLoadError(
                f"row {rid}: 'label' must be one of {VALID_LABELS!r}, got {label!r}"
            )
        if not isinstance(provenance, str) or not provenance.strip():
            raise SeedLoadError(
                f"row {rid}: 'provenance' MUST be a non-empty citation string"
            )
        recorded_verdict = row.get("recorded_verdict")
        if recorded_verdict is not None and recorded_verdict not in VALID_VERDICTS:
            raise SeedLoadError(
                f"row {rid}: 'recorded_verdict' must be one of {VALID_VERDICTS!r} or null"
            )
        recorded_confidence = _validate_confidence(
            row.get("recorded_confidence"),
            field_name="recorded_confidence",
            row_id=rid,
        )
        parsed.append(SeedClaim(
            claim_id=rid,
            claim=claim,
            evidence=evidence,
            label=label,
            provenance=provenance,
            recorded_verdict=recorded_verdict,
            recorded_confidence=recorded_confidence,
        ))
    if not parsed:
        raise SeedLoadError(f"seed file {path} contains no rows")
    return parsed


# ---------------------------------------------------------------------------
# Calibration scoring.
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CalibrationSummary:
    """Aggregate calibration metrics for one seed set.

    ``n_scored`` is the count of rows that entered scoring -- rows with
    ``label == "inconclusive"`` are excluded because there is no truthy
    correctness to check against a numeric confidence. ``ece`` is the
    Expected Calibration Error over 10 confidence buckets, ``brier`` is
    the Brier score, ``interval_lo`` / ``interval_hi`` are the two-sided
    95% Wilson interval on ``accuracy``.
    """
    n_scored: int
    n_skipped_inconclusive: int
    accuracy: float
    ece: float
    brier: float
    interval_lo: float
    interval_hi: float
    per_bucket_curve: list[dict[str, float]] = field(default_factory=list)


def _pair_for_calibration(
    predicted_verdict: str,
    predicted_confidence: float | None,
    label: str,
) -> tuple[float, bool] | None:
    """Return ``(confidence, correct)`` for one row, or None to skip it."""
    if label == "inconclusive":
        return None
    if predicted_confidence is None:
        return None
    correct = predicted_verdict == label
    return (float(predicted_confidence), correct)


def score_calibration_from_recorded(
    seed: Sequence[SeedClaim],
    *,
    n_buckets: int = 10,
) -> CalibrationSummary:
    """Compute calibration metrics from the seed's ``recorded_*`` fields.

    Requires each scored row to carry both ``recorded_verdict`` and
    ``recorded_confidence``. Rows with ``label == "inconclusive"`` or a
    missing ``recorded_confidence`` are skipped. Useful for scoring a
    static seed of historical verifier outputs without re-invoking the
    LLM.
    """
    confs: list[float] = []
    correct: list[bool] = []
    skipped_inc = 0
    for row in seed:
        if row.label == "inconclusive":
            skipped_inc += 1
            continue
        if row.recorded_verdict is None or row.recorded_confidence is None:
            continue
        pair = _pair_for_calibration(row.recorded_verdict, row.recorded_confidence, row.label)
        if pair is None:
            continue
        confs.append(pair[0])
        correct.append(pair[1])
    return _summarize(confs, correct, skipped_inc, n_buckets=n_buckets)


async def score_calibration(
    verifier_fn: VerifierFn,
    seed: Sequence[SeedClaim],
    *,
    n_buckets: int = 10,
) -> CalibrationSummary:
    """Run the verifier over every seed row and compute calibration metrics.

    Rows with ``label == "inconclusive"`` are counted in the returned
    ``n_skipped_inconclusive`` but excluded from ECE / Brier / accuracy
    because there is no boolean correctness to score against a numeric
    confidence.
    """
    confs: list[float] = []
    correct: list[bool] = []
    skipped_inc = 0
    for row in seed:
        verdict = await verifier_fn(claim=row.claim, evidence=row.evidence)
        if row.label == "inconclusive":
            skipped_inc += 1
            continue
        pair = _pair_for_calibration(verdict.verdict, verdict.confidence, row.label)
        if pair is None:
            continue
        confs.append(pair[0])
        correct.append(pair[1])
    return _summarize(confs, correct, skipped_inc, n_buckets=n_buckets)


def _summarize(
    confs: list[float],
    correct: list[bool],
    skipped_inc: int,
    *,
    n_buckets: int,
) -> CalibrationSummary:
    n = len(confs)
    successes = sum(1 for ok in correct if ok)
    accuracy = (successes / n) if n else 0.0
    lo, hi = wilson_interval(successes, n)
    curve = calibration_curve(confs, correct, n_buckets=n_buckets)
    per_bucket = [
        {
            "lo": b.lo,
            "hi": b.hi,
            "count": float(b.count),
            "mean_confidence": b.mean_confidence,
            "accuracy": b.accuracy,
        }
        for b in curve
    ]
    return CalibrationSummary(
        n_scored=n,
        n_skipped_inconclusive=skipped_inc,
        accuracy=accuracy,
        ece=ece(confs, correct, n_buckets=n_buckets),
        brier=brier_score(confs, correct),
        interval_lo=lo,
        interval_hi=hi,
        per_bucket_curve=per_bucket,
    )


# ---------------------------------------------------------------------------
# Bias stress tests -- label-INDEPENDENT.
# ---------------------------------------------------------------------------


def permute_evidence_sections(evidence: str, *, rng: random.Random) -> str:
    """Return ``evidence`` with its paragraph-level sections permuted.

    ``_render_verdict_input`` in the claim verifier composes the user
    message as ``## <precondition id>: <claim>`` sections separated by
    blank lines, then one final instruction line. This helper permutes
    the top-level paragraph blocks (split on blank lines) while leaving
    each block internally intact. When only one block exists the string
    is returned unchanged and ``verdict_stable`` will trivially be True
    on that row -- flagging the caller that the perturbation was a
    no-op there rather than crashing.
    """
    blocks = [b for b in evidence.split("\n\n") if b.strip()]
    if len(blocks) < 2:
        return evidence
    # Guarantee an actual permutation (not the identity) so the stability
    # check isn't accidentally satisfied by an unchanged input on small N.
    permuted = list(blocks)
    for _ in range(64):
        rng.shuffle(permuted)
        if permuted != blocks:
            break
    return "\n\n".join(permuted)


def verbose_pad_claim(claim: str, *, filler_multiplier: int = 3) -> str:
    """Return ``claim`` padded with ``filler_multiplier`` irrelevant paragraphs.

    The filler is a fixed neutral context paragraph that carries no
    security-relevant tokens (no CVE ids, no sink names, no function
    identifiers) so a well-calibrated verifier should ignore it and
    produce the same verdict + a near-identical confidence.
    """
    if filler_multiplier < 1:
        raise ValueError("filler_multiplier must be >= 1")
    padding = ("\n\n" + _FILLER_PARAGRAPH) * filler_multiplier
    return claim + padding


@dataclass(frozen=True, slots=True)
class BiasCase:
    """One row's baseline vs perturbed verifier output."""
    claim_id: str
    baseline: VerifierVerdict
    perturbed: VerifierVerdict
    verdict_stable: bool
    confidence_delta: float


@dataclass(frozen=True, slots=True)
class BiasSummary:
    """Aggregate result of one bias stress pass."""
    name: str
    n: int
    n_stable: int
    verdict_flip_rate: float
    mean_abs_confidence_delta: float
    max_abs_confidence_delta: float
    unstable: list[BiasCase] = field(default_factory=list)


async def _run_bias_pass(
    name: str,
    verifier_fn: VerifierFn,
    seed: Sequence[SeedClaim],
    perturb: Callable[[SeedClaim], tuple[str, str]],
) -> BiasSummary:
    cases: list[BiasCase] = []
    unstable: list[BiasCase] = []
    total_abs_delta = 0.0
    max_abs_delta = 0.0
    for row in seed:
        baseline = await verifier_fn(claim=row.claim, evidence=row.evidence)
        perturbed_claim, perturbed_evidence = perturb(row)
        perturbed = await verifier_fn(claim=perturbed_claim, evidence=perturbed_evidence)
        stable = baseline.verdict == perturbed.verdict
        delta = perturbed.confidence - baseline.confidence
        abs_delta = abs(delta)
        total_abs_delta += abs_delta
        if abs_delta > max_abs_delta:
            max_abs_delta = abs_delta
        case = BiasCase(
            claim_id=row.claim_id,
            baseline=baseline,
            perturbed=perturbed,
            verdict_stable=stable,
            confidence_delta=delta,
        )
        cases.append(case)
        if not stable:
            unstable.append(case)
    n = len(cases)
    n_stable = sum(1 for c in cases if c.verdict_stable)
    flip_rate = (n - n_stable) / n if n else 0.0
    mean_abs = (total_abs_delta / n) if n else 0.0
    return BiasSummary(
        name=name,
        n=n,
        n_stable=n_stable,
        verdict_flip_rate=flip_rate,
        mean_abs_confidence_delta=mean_abs,
        max_abs_confidence_delta=max_abs_delta,
        unstable=unstable,
    )


async def stress_position_bias(
    verifier_fn: VerifierFn,
    seed: Sequence[SeedClaim],
    *,
    seed_rng: int = 0,
) -> BiasSummary:
    """Measure verdict / confidence drift when evidence sections are permuted.

    Passes each row through ``verifier_fn`` twice: once with the original
    evidence, once with the top-level paragraph blocks permuted by a
    deterministic ``random.Random(seed_rng)``. Reports how many verdicts
    flipped and the mean / max absolute confidence delta so the operator
    can set a stability floor on the verdict prompt version.
    """
    rng = random.Random(seed_rng)
    def _perturb(row: SeedClaim) -> tuple[str, str]:
        return row.claim, permute_evidence_sections(row.evidence, rng=rng)
    return await _run_bias_pass("position", verifier_fn, seed, _perturb)


async def stress_verbosity_bias(
    verifier_fn: VerifierFn,
    seed: Sequence[SeedClaim],
    *,
    filler_multiplier: int = 3,
) -> BiasSummary:
    """Measure verdict / confidence drift when the claim is padded with filler.

    Passes each row through ``verifier_fn`` twice: once with the original
    claim, once with :func:`verbose_pad_claim` appended
    ``filler_multiplier`` times. A verdict that flips or a confidence
    that swings under content-free padding indicates the verifier is
    keying on prompt length instead of probe evidence.
    """
    def _perturb(row: SeedClaim) -> tuple[str, str]:
        return verbose_pad_claim(row.claim, filler_multiplier=filler_multiplier), row.evidence
    return await _run_bias_pass("verbosity", verifier_fn, seed, _perturb)


# ---------------------------------------------------------------------------
# CLI entrypoint.
# ---------------------------------------------------------------------------


def _format_summary(cal: CalibrationSummary) -> str:
    lines = [
        "== calibration (from recorded verdicts) ==",
        f"  n_scored:                  {cal.n_scored}",
        f"  n_skipped_inconclusive:    {cal.n_skipped_inconclusive}",
        f"  accuracy:                  {cal.accuracy:.4f}",
        f"  ECE (10 buckets):          {cal.ece:.4f}",
        f"  Brier score:               {cal.brier:.4f}",
        (
            f"  95% Wilson interval:       [{cal.interval_lo:.4f}, "
            f"{cal.interval_hi:.4f}]  (width {cal.interval_hi - cal.interval_lo:.4f})"
        ),
    ]
    if cal.per_bucket_curve:
        lines.append("  reliability diagram:")
        for b in cal.per_bucket_curve:
            lines.append(
                f"    [{b['lo']:.1f}, {b['hi']:.1f})  n={int(b['count']):>3}  "
                f"mean_conf={b['mean_confidence']:.3f}  acc={b['accuracy']:.3f}"
            )
    return "\n".join(lines)


def _format_bias(bias: BiasSummary) -> str:
    lines = [
        f"== bias stress: {bias.name} ==",
        f"  n:                         {bias.n}",
        f"  n_stable:                  {bias.n_stable}",
        f"  verdict flip rate:         {bias.verdict_flip_rate:.4f}",
        f"  mean |confidence delta|:   {bias.mean_abs_confidence_delta:.4f}",
        f"  max  |confidence delta|:   {bias.max_abs_confidence_delta:.4f}",
    ]
    if bias.unstable:
        lines.append(f"  unstable rows ({len(bias.unstable)}):")
        for c in bias.unstable[:20]:
            lines.append(
                f"    {c.claim_id}: {c.baseline.verdict}@{c.baseline.confidence:.2f} "
                f"-> {c.perturbed.verdict}@{c.perturbed.confidence:.2f}"
            )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI: ``python -m aila.platform.eval.judge_harness --seed <path>``.

    Reads the seed file, scores calibration from the recorded verdicts
    (which lets the CLI run without invoking any LLM), and prints ECE /
    Brier / interval width plus a per-bucket reliability diagram.
    Returns 0 on success, 2 on seed-load failure.
    """
    parser = argparse.ArgumentParser(
        prog="python -m aila.platform.eval.judge_harness",
        description=(
            "Judge-reliability harness for the claim verifier: calibration "
            "metrics (ECE / Brier / Wilson interval) and label-independent "
            "bias stress test scaffolding (position + verbosity)."
        ),
    )
    parser.add_argument(
        "--seed",
        type=Path,
        default=BOOTSTRAP_SEED_PATH,
        help=(
            "Path to a JSON seed file. Defaults to the bundled "
            "bootstrap_judge_seed.json next to this module."
        ),
    )
    parser.add_argument(
        "--buckets",
        type=int,
        default=10,
        help="Number of confidence buckets for the ECE / reliability diagram (default: 10).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the calibration summary as JSON instead of the human-readable report.",
    )
    args = parser.parse_args(argv)
    try:
        rows = load_seed(args.seed)
    except SeedLoadError as exc:
        print(f"seed load failed: {exc}", file=sys.stderr)
        return 2
    cal = score_calibration_from_recorded(rows, n_buckets=args.buckets)
    if args.json:
        out = {
            "seed_path": str(args.seed),
            "n_rows_total": len(rows),
            "calibration": {
                "n_scored": cal.n_scored,
                "n_skipped_inconclusive": cal.n_skipped_inconclusive,
                "accuracy": cal.accuracy,
                "ece": cal.ece,
                "brier": cal.brier,
                "interval_lo": cal.interval_lo,
                "interval_hi": cal.interval_hi,
                "interval_width": cal.interval_hi - cal.interval_lo,
                "per_bucket_curve": cal.per_bucket_curve,
            },
            "bias_stress": {
                "note": (
                    "position/verbosity bias stress requires a live verifier; "
                    "invoke stress_position_bias / stress_verbosity_bias from a "
                    "CI job that has a VerifierFn wired to ClaimVerifierAgentBase.run"
                ),
            },
        }
        print(json.dumps(out, indent=2, sort_keys=True))
        return 0
    print(f"seed: {args.seed}  (rows: {len(rows)})")
    print(_format_summary(cal))
    print()
    print(
        "note: position/verbosity bias stress requires a live verifier;\n"
        "      call stress_position_bias / stress_verbosity_bias from a\n"
        "      CI adapter that binds ClaimVerifierAgentBase.run behind the\n"
        "      VerifierFn protocol."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
