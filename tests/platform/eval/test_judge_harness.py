"""Tests for the judge-reliability harness (issue #152).

Three groups:

1. Known-answer calibration metrics (:func:`aila.platform.eval.judge_harness.brier_score`,
   :func:`wilson_interval`, and the reused :func:`ece`) on hand-built
   perfectly-calibrated and maximally-overconfident inputs.
2. Bias-stress harness detects an injected instability using stub
   verifiers -- one that flips verdict on evidence reorder and one that
   swings confidence on claim padding.
3. Seed loader parses the bundled bootstrap seed and refuses malformed
   rows.
"""
from __future__ import annotations

import json
import random
from pathlib import Path

import pytest

from aila.platform.eval.judge_harness import (
    BOOTSTRAP_SEED_PATH,
    SeedClaim,
    SeedLoadError,
    VerifierVerdict,
    brier_score,
    load_seed,
    main,
    permute_evidence_sections,
    score_calibration,
    score_calibration_from_recorded,
    stress_position_bias,
    stress_verbosity_bias,
    verbose_pad_claim,
    wilson_interval,
)
from aila.platform.eval.metrics import ece

# --------------------------------------------------------------------- #
#  1. Known-answer calibration metrics
# --------------------------------------------------------------------- #


class TestBrierScore:
    def test_perfect_forecaster_scores_zero(self) -> None:
        # Confidence 1.0 on every correct call, 0.0 on every wrong call:
        # (1-1)^2 + (0-0)^2 + (1-1)^2 = 0.
        assert brier_score([1.0, 0.0, 1.0], [True, False, True]) == pytest.approx(0.0)

    def test_maximally_overconfident_wrong_scores_one(self) -> None:
        # Confidence 1.0 on every wrong answer: (1-0)^2 = 1 for each row.
        assert brier_score([1.0, 1.0, 1.0], [False, False, False]) == pytest.approx(1.0)

    def test_hand_computed_matches(self) -> None:
        # ((0.8-1)^2 + (0.3-0)^2 + (0.6-1)^2 + (0.9-0)^2) / 4
        # = (0.04 + 0.09 + 0.16 + 0.81) / 4 = 0.275
        assert brier_score([0.8, 0.3, 0.6, 0.9], [True, False, True, False]) == pytest.approx(
            0.275, abs=1e-9,
        )

    def test_empty_returns_zero(self) -> None:
        assert brier_score([], []) == 0.0

    def test_length_mismatch_raises(self) -> None:
        with pytest.raises(ValueError):
            brier_score([0.5], [True, False])


class TestECEKnownAnswers:
    """Sanity-check the reused ECE metric behaves as documented on the two
    endpoint fixtures the harness's CLI reports live: perfectly calibrated
    (ECE = 0) and maximally overconfident (ECE ~= 1).
    """
    def test_perfectly_calibrated_binary_endpoint(self) -> None:
        # Two buckets each perfectly matching their confidence.
        assert ece([1.0, 1.0, 0.0, 0.0], [True, True, False, False]) == pytest.approx(0.0)

    def test_maximally_overconfident_is_high(self) -> None:
        # Confidence 1.0 on every wrong answer -> ECE = |1.0 - 0.0| = 1.0.
        assert ece([1.0, 1.0, 1.0, 1.0], [False, False, False, False]) == pytest.approx(1.0)

    def test_verifier_prompt_anchor_bands_when_calibrated(self) -> None:
        """Rows at each anchor band the verdict prompt names (0.5 / 0.7 / 0.9)
        with accuracy matching the band's mean confidence should score ~= 0.
        """
        confs = [0.9] * 10 + [0.7] * 10 + [0.5] * 10
        # 9/10 correct in the 0.9 band, 7/10 in the 0.7 band, 5/10 in the 0.5 band.
        correct = ([True] * 9 + [False]) + ([True] * 7 + [False] * 3) + ([True] * 5 + [False] * 5)
        assert ece(confs, correct) == pytest.approx(0.0, abs=1e-9)


class TestWilsonInterval:
    def test_full_success_upper_at_one(self) -> None:
        lo, hi = wilson_interval(10, 10)
        assert 0.0 < lo < 1.0
        assert hi == pytest.approx(1.0, abs=1e-6) or hi > 0.99

    def test_zero_success_lower_at_zero(self) -> None:
        lo, hi = wilson_interval(0, 10)
        assert lo == 0.0
        assert 0.0 < hi < 1.0

    def test_zero_n_covers_full_range(self) -> None:
        # No data -- honest report is "we don't know".
        assert wilson_interval(0, 0) == (0.0, 1.0)

    def test_interval_shrinks_with_n(self) -> None:
        lo10, hi10 = wilson_interval(5, 10)
        lo1000, hi1000 = wilson_interval(500, 1000)
        assert (hi10 - lo10) > (hi1000 - lo1000)

    def test_rejects_bad_inputs(self) -> None:
        with pytest.raises(ValueError):
            wilson_interval(5, -1)
        with pytest.raises(ValueError):
            wilson_interval(11, 10)
        with pytest.raises(ValueError):
            wilson_interval(-1, 10)


# --------------------------------------------------------------------- #
#  2. Bias stress harness detects injected instability
# --------------------------------------------------------------------- #


def _make_row(claim_id: str, *, claim: str, evidence: str, label: str = "confirmed") -> SeedClaim:
    return SeedClaim(
        claim_id=claim_id,
        claim=claim,
        evidence=evidence,
        label=label,
        provenance="unit-test-fixture",
    )


def _multi_section_evidence(n: int = 4) -> str:
    return "\n\n".join(f"## P{i}: precondition {i}\nprobe_result: match" for i in range(n))


class TestPermuteEvidenceSections:
    def test_paragraphs_actually_permute(self) -> None:
        evidence = _multi_section_evidence(4)
        permuted = permute_evidence_sections(evidence, rng=random.Random(0))
        assert permuted != evidence
        # Same block set, different order.
        assert set(permuted.split("\n\n")) == set(evidence.split("\n\n"))

    def test_single_section_unchanged(self) -> None:
        evidence = "only one block"
        assert permute_evidence_sections(evidence, rng=random.Random(0)) == evidence


class _StubStableVerifier:
    """Always returns the same verdict + confidence regardless of input."""
    def __init__(self, verdict: str = "confirmed", confidence: float = 0.85) -> None:
        self._verdict = verdict
        self._confidence = confidence

    async def __call__(self, *, claim: str, evidence: str) -> VerifierVerdict:
        del claim, evidence
        return VerifierVerdict(verdict=self._verdict, confidence=self._confidence)


class _StubOrderSensitiveVerifier:
    """Flips verdict when the FIRST block of evidence changes.

    Mirrors the bias mode the position stress test is designed to catch:
    an LLM verifier that keys on evidence order (typical failure mode for
    "compare A vs B" prompts) will change its answer when the same probe
    results are shown in a different order.
    """
    def __init__(self) -> None:
        self._first_block_to_verdict = {"## P0: precondition 0\nprobe_result: match": "confirmed"}

    async def __call__(self, *, claim: str, evidence: str) -> VerifierVerdict:
        del claim
        first_block = evidence.split("\n\n", 1)[0]
        if first_block == "## P0: precondition 0\nprobe_result: match":
            return VerifierVerdict(verdict="confirmed", confidence=0.9)
        return VerifierVerdict(verdict="refuted", confidence=0.6)


class _StubVerbositySensitiveVerifier:
    """Confidence collapses when the claim is padded with filler text.

    Mirrors the bias the verbosity stress test is designed to catch:
    an LLM verifier that keys on claim length rather than probe evidence
    will drift as filler is appended.
    """
    def __init__(self, baseline_len: int) -> None:
        self._baseline_len = baseline_len

    async def __call__(self, *, claim: str, evidence: str) -> VerifierVerdict:
        del evidence
        if len(claim) > self._baseline_len + 50:
            # Padded input: swing to a much lower confidence.
            return VerifierVerdict(verdict="confirmed", confidence=0.30)
        return VerifierVerdict(verdict="confirmed", confidence=0.90)


class TestPositionBiasStress:
    @pytest.mark.asyncio
    async def test_stable_verifier_reports_zero_flip_rate(self) -> None:
        seed = [_make_row(f"row-{i}", claim="c", evidence=_multi_section_evidence(4)) for i in range(3)]
        summary = await stress_position_bias(_StubStableVerifier(), seed)
        assert summary.n == 3
        assert summary.verdict_flip_rate == pytest.approx(0.0)
        assert summary.mean_abs_confidence_delta == pytest.approx(0.0)
        assert summary.unstable == []

    @pytest.mark.asyncio
    async def test_flipping_verifier_is_detected(self) -> None:
        # Larger N + fixed rng so the permutation displaces P0 on a
        # supermajority of rows (with 4 blocks a uniformly random
        # non-identity permutation leaves P0 in the leading slot ~25%
        # of the time, so we expect ~75% flip rate).
        seed = [_make_row(f"row-{i}", claim="c", evidence=_multi_section_evidence(4)) for i in range(20)]
        summary = await stress_position_bias(_StubOrderSensitiveVerifier(), seed, seed_rng=42)
        assert summary.n == 20
        # A stable verifier scores 0.0 -- this bias detection MUST
        # produce a clearly-nonzero flip rate on this stub.
        assert summary.verdict_flip_rate > 0.5, (
            f"expected >0.5 flip rate on the order-sensitive stub, "
            f"got {summary.verdict_flip_rate}"
        )
        assert summary.unstable  # at least one flip surfaced
        # Every flip has confidence delta |0.6 - 0.9| = 0.3.
        for case in summary.unstable:
            assert abs(case.confidence_delta) == pytest.approx(0.3, abs=1e-9)
        assert summary.max_abs_confidence_delta == pytest.approx(0.3, abs=1e-9)


class TestVerbosityBiasStress:
    @pytest.mark.asyncio
    async def test_stable_verifier_reports_zero_drift(self) -> None:
        seed = [_make_row(f"row-{i}", claim="short claim", evidence="e") for i in range(3)]
        summary = await stress_verbosity_bias(_StubStableVerifier(), seed)
        assert summary.n == 3
        assert summary.verdict_flip_rate == pytest.approx(0.0)
        assert summary.mean_abs_confidence_delta == pytest.approx(0.0)

    @pytest.mark.asyncio
    async def test_confidence_swing_under_padding_is_detected(self) -> None:
        base_claim = "short claim"
        seed = [_make_row(f"row-{i}", claim=base_claim, evidence="e") for i in range(4)]
        verifier = _StubVerbositySensitiveVerifier(baseline_len=len(base_claim))
        summary = await stress_verbosity_bias(verifier, seed, filler_multiplier=3)
        assert summary.n == 4
        # Verdicts don't flip but confidence swings 0.60 on every row.
        assert summary.verdict_flip_rate == pytest.approx(0.0)
        assert summary.mean_abs_confidence_delta == pytest.approx(0.60, abs=1e-9)
        assert summary.max_abs_confidence_delta == pytest.approx(0.60, abs=1e-9)

    def test_verbose_pad_claim_appends_filler(self) -> None:
        base = "the claim text"
        padded = verbose_pad_claim(base, filler_multiplier=2)
        assert padded.startswith(base)
        # Two filler paragraphs appended.
        assert padded.count("prior investigations in this workspace") == 2

    def test_verbose_pad_claim_rejects_zero_multiplier(self) -> None:
        with pytest.raises(ValueError):
            verbose_pad_claim("x", filler_multiplier=0)


# --------------------------------------------------------------------- #
#  Score-calibration end-to-end with a stub verifier
# --------------------------------------------------------------------- #


class _StubOracleVerifier:
    """Verifier that always emits the row's ground-truth label at confidence 1.0.

    Wired to prove the async score_calibration pipeline reaches the metric
    layer with the right shape -- with a perfectly-oracular verifier on a
    labeled seed, ECE and Brier should both floor at 0.0.
    """
    def __init__(self, seed_by_id: dict[str, SeedClaim]) -> None:
        self._seed_by_id = seed_by_id

    async def __call__(self, *, claim: str, evidence: str) -> VerifierVerdict:
        del evidence
        for row in self._seed_by_id.values():
            if row.claim == claim:
                return VerifierVerdict(verdict=row.label, confidence=1.0)
        return VerifierVerdict(verdict="inconclusive", confidence=0.5)


class TestScoreCalibration:
    @pytest.mark.asyncio
    async def test_oracle_verifier_scores_perfectly(self) -> None:
        seed = [
            _make_row("r1", claim="claim-a", evidence="e", label="confirmed"),
            _make_row("r2", claim="claim-b", evidence="e", label="refuted"),
            _make_row("r3", claim="claim-c", evidence="e", label="confirmed"),
        ]
        by_id = {r.claim_id: r for r in seed}
        summary = await score_calibration(_StubOracleVerifier(by_id), seed)
        assert summary.n_scored == 3
        assert summary.n_skipped_inconclusive == 0
        assert summary.accuracy == pytest.approx(1.0)
        assert summary.ece == pytest.approx(0.0)
        assert summary.brier == pytest.approx(0.0)

    @pytest.mark.asyncio
    async def test_inconclusive_labeled_rows_are_skipped(self) -> None:
        seed = [
            _make_row("r1", claim="a", evidence="e", label="inconclusive"),
            _make_row("r2", claim="b", evidence="e", label="confirmed"),
        ]
        by_id = {r.claim_id: r for r in seed}
        summary = await score_calibration(_StubOracleVerifier(by_id), seed)
        assert summary.n_scored == 1
        assert summary.n_skipped_inconclusive == 1


# --------------------------------------------------------------------- #
#  3. Seed loader
# --------------------------------------------------------------------- #


class TestSeedLoader:
    def test_bootstrap_seed_parses(self) -> None:
        rows = load_seed(BOOTSTRAP_SEED_PATH)
        assert rows, "bootstrap seed must ship with at least one row"
        for row in rows:
            assert row.claim.strip()
            assert row.evidence.strip()
            assert row.provenance.strip()
            assert row.label in ("confirmed", "refuted", "inconclusive")

    def test_bootstrap_seed_has_provenance_meta(self) -> None:
        raw = json.loads(BOOTSTRAP_SEED_PATH.read_text(encoding="utf-8"))
        meta = raw.get("_meta", {})
        assert "sources" in meta
        assert isinstance(meta["sources"], list) and meta["sources"]
        # Every row cites its source.
        for row in raw["rows"]:
            assert row["provenance"].strip()

    def test_bootstrap_seed_from_recorded_is_shape_smoke(self) -> None:
        """The bootstrap's ``label`` equals ``recorded_verdict`` by
        construction (documented in _meta.bootstrap_notice), so accuracy
        is trivially 1.0 -- this only proves the metric plumbing runs
        end-to-end. ECE and Brier are NOT expected to be 0 on the
        bootstrap because some recorded_confidence values are low (a
        ``refuted`` verdict with recorded_confidence=0.15 that matches
        its label counts as correct but underconfident, which drives
        ECE up). This asymmetry is intentional -- the bootstrap is
        exercising the underconfidence detection path too.
        """
        rows = load_seed(BOOTSTRAP_SEED_PATH)
        summary = score_calibration_from_recorded(rows)
        assert summary.n_scored >= 1
        assert summary.n_skipped_inconclusive >= 1
        assert summary.accuracy == pytest.approx(1.0)
        # Sanity bounds: metrics are in their valid ranges.
        assert 0.0 <= summary.ece <= 1.0
        assert 0.0 <= summary.brier <= 1.0
        assert 0.0 <= summary.interval_lo <= summary.interval_hi <= 1.0

    def test_missing_provenance_rejected(self, tmp_path: Path) -> None:
        seed = {
            "rows": [
                {
                    "claim_id": "bad", "claim": "c", "evidence": "e",
                    "label": "confirmed", "provenance": "",
                },
            ],
        }
        p = tmp_path / "seed.json"
        p.write_text(json.dumps(seed), encoding="utf-8")
        with pytest.raises(SeedLoadError, match="provenance"):
            load_seed(p)

    def test_invalid_label_rejected(self, tmp_path: Path) -> None:
        seed = {
            "rows": [
                {
                    "claim_id": "bad", "claim": "c", "evidence": "e",
                    "label": "maybe", "provenance": "src",
                },
            ],
        }
        p = tmp_path / "seed.json"
        p.write_text(json.dumps(seed), encoding="utf-8")
        with pytest.raises(SeedLoadError, match="label"):
            load_seed(p)

    def test_out_of_range_recorded_confidence_rejected(self, tmp_path: Path) -> None:
        seed = {
            "rows": [
                {
                    "claim_id": "bad", "claim": "c", "evidence": "e",
                    "label": "confirmed", "provenance": "src",
                    "recorded_verdict": "confirmed",
                    "recorded_confidence": 1.5,
                },
            ],
        }
        p = tmp_path / "seed.json"
        p.write_text(json.dumps(seed), encoding="utf-8")
        with pytest.raises(SeedLoadError, match="recorded_confidence"):
            load_seed(p)

    def test_empty_seed_rejected(self, tmp_path: Path) -> None:
        p = tmp_path / "seed.json"
        p.write_text(json.dumps({"rows": []}), encoding="utf-8")
        with pytest.raises(SeedLoadError, match="no rows"):
            load_seed(p)

    def test_malformed_json_rejected(self, tmp_path: Path) -> None:
        p = tmp_path / "seed.json"
        p.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(SeedLoadError, match="JSON"):
            load_seed(p)


# --------------------------------------------------------------------- #
#  CLI smoke test -- the runnable entrypoint prints metrics
# --------------------------------------------------------------------- #


class TestCLIEntrypoint:
    def test_help_exits_cleanly(self, capsys: pytest.CaptureFixture[str]) -> None:

        with pytest.raises(SystemExit) as exc:
            main(["--help"])
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "--seed" in out
        assert "judge" in out.lower()

    def test_run_on_bootstrap_seed_prints_metrics(self, capsys: pytest.CaptureFixture[str]) -> None:

        rc = main(["--seed", str(BOOTSTRAP_SEED_PATH)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "ECE" in out
        assert "Brier score" in out
        assert "Wilson interval" in out

    def test_run_json_mode(self, capsys: pytest.CaptureFixture[str]) -> None:

        rc = main(["--seed", str(BOOTSTRAP_SEED_PATH), "--json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["calibration"]["accuracy"] == pytest.approx(1.0)
        assert 0.0 <= payload["calibration"]["ece"] <= 1.0
        assert 0.0 <= payload["calibration"]["brier"] <= 1.0
        assert "interval_width" in payload["calibration"]

    def test_bad_seed_returns_error_code(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:

        p = tmp_path / "bad.json"
        p.write_text("{not json", encoding="utf-8")
        rc = main(["--seed", str(p)])
        assert rc == 2
        err = capsys.readouterr().err
        assert "seed load failed" in err
