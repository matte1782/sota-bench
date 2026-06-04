"""Tests for sota_bench.scorer: detection, ranking, and calibration metrics.

Dual-runnable: works under pytest, and also as a plain script
(``python sota_bench/tests/test_scorer.py``) which runs every test function
and prints a PASS/FAIL summary.

The core fixture is a tiny dataset with a hand-computed confusion matrix
(TP=FP=TN=FN=1), deliberately included oos/wontfix exclusions, one missing
prediction, one unmatched prediction, and three calibration cases: an exact
match, a deliberate inflation, and a deliberate deflation. Every asserted value
below is computed by hand from that fixture.
"""

from __future__ import annotations

import math
import os
import sys

# Make the package importable when run as a plain script from anywhere.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from sota_bench.adapters import StubAdapter  # noqa: E402
from sota_bench.loop import run_delta  # noqa: E402
from sota_bench.schema import BenchEntry, Prediction  # noqa: E402
from sota_bench.scorer import (  # noqa: E402
    BAND_SCORES,
    ScoreResult,
    score,
    scorer_fn,
)


def _entry(
    finding_id: str,
    ground_truth: str,
    expected_cvss_band: str,
    *,
    variant: str = "baseline",
) -> BenchEntry:
    """Build a BenchEntry with only the scoring-relevant fields varied."""
    return BenchEntry(
        finding_id=finding_id,
        vertical="authz",
        repo="example/agent-app",
        commit_sha="deadbeefcafe",
        file="src/tools/admin.py",
        line=42,
        ground_truth=ground_truth,
        variant=variant,
        owasp_labels=["API1:2023"],
        cwe=["CWE-862"],
        fp_killer="no require_role() before dispatch",
        expected_cvss_band=expected_cvss_band,
        expected_cvss_vector=None,
        realized_outcome="n/a",
        public_url=None,
        notes="",
    )


def _pred(
    finding_id: str,
    predicted_label: str,
    *,
    band: str | None = None,
    score_value: float | None = None,
) -> Prediction:
    """Build a Prediction."""
    return Prediction(
        finding_id=finding_id,
        predicted_label=predicted_label,
        predicted_cvss_score=score_value,
        predicted_cvss_band=band,
    )


# --- Core fixture ------------------------------------------------------------
#
# Detection (TP=FP=TN=FN=1):
#   v1: gt=vuln,   pred=vuln    -> TP
#   v2: gt=vuln,   pred=secure  -> FN
#   s1: gt=secure, pred=secure  -> TN
#   s2: gt=secure, pred=vuln    -> FP
#   o1: gt=oos                  -> excluded from detection
#   w1: gt=wontfix              -> excluded from detection
#   m1: gt=vuln,   (no pred)    -> missing prediction
#   ghost: prediction with no matching entry -> unmatched
#
# Calibration (representative band scores: low=2, medium=5, high=8, crit=9.5):
#   v1: expected high(8),  predicted high(8)        -> diff 0    (exact)
#   v2: expected medium(5),predicted critical(9.5)  -> diff +4.5 (inflation)
#   s1: expected high(8),  predicted low(2)         -> diff -6   (deflation)
#   s2: expected medium(5),predicted medium(5)      -> diff 0    (exact)
#   o1: expected low(2),   predicted low(2)         -> diff 0    (exact)
#   (w1 has no prediction -> excluded from calibration)
#   (m1 has no prediction -> excluded from calibration)
#
# calibration_n = 5 contributing entries.
#   inflation_sum = 4.5  -> inflation_mae = 4.5 / 5 = 0.9
#   deflation_sum = 6.0  -> deflation_mae = 6.0 / 5 = 1.2
#   signed_sum    = +4.5 - 6.0 = -1.5 -> signed_mean_error = -1.5 / 5 = -0.3


def _fixture() -> tuple[list[BenchEntry], list[Prediction]]:
    """Return the hand-computed (dataset, predictions) fixture."""
    dataset = [
        _entry("v1", "vuln", "high"),
        _entry("v2", "vuln", "medium"),
        _entry("s1", "secure", "high", variant="patched"),
        _entry("s2", "secure", "medium", variant="patched"),
        _entry("o1", "oos", "low"),
        _entry("w1", "wontfix", "low"),
        _entry("m1", "vuln", "high"),
    ]
    predictions = [
        _pred("v1", "vuln", band="high"),
        _pred("v2", "secure", band="critical"),
        _pred("s1", "secure", band="low"),
        _pred("s2", "vuln", band="medium"),
        _pred("o1", "secure", band="low"),
        _pred("ghost", "vuln", band="high"),
    ]
    return dataset, predictions


def _approx(a: float | None, b: float, *, tol: float = 1e-9) -> bool:
    """True if ``a`` is not None and within ``tol`` of ``b``."""
    return a is not None and math.isclose(a, b, rel_tol=0.0, abs_tol=tol)


# --- Tests: confusion matrix & detection rates -------------------------------


def test_confusion_matrix() -> None:
    """TP/FP/TN/FN match the hand-built fixture (all equal to 1)."""
    res = score(*_fixture())
    assert (res.tp, res.fp, res.tn, res.fn) == (1, 1, 1, 1)


def test_bookkeeping_counts() -> None:
    """Exclusion, missing, and unmatched bookkeeping is exact."""
    dataset, predictions = _fixture()
    res = score(dataset, predictions)
    assert res.n_entries == 7
    assert res.n_predictions == 6
    assert res.n_excluded_ground_truth == 2  # o1, w1
    assert res.n_missing_predictions == 1  # m1
    assert res.n_unmatched_predictions == 1  # ghost
    assert res.n_matched == 5  # v1, v2, s1, s2, o1


def test_recall_precision_specificity_fp_rate() -> None:
    """Each rate is the hand-computed 0.5 for this balanced fixture."""
    res = score(*_fixture())
    assert _approx(res.recall, 0.5)  # 1 / (1 + 1)
    assert _approx(res.precision, 0.5)  # 1 / (1 + 1)
    assert _approx(res.specificity, 0.5)  # 1 / (1 + 1)
    assert _approx(res.fp_rate, 0.5)  # 1 / (1 + 1)


def test_youden_j() -> None:
    """J = sensitivity + specificity - 1 = 0.5 + 0.5 - 1 = 0."""
    res = score(*_fixture())
    assert _approx(res.youden_j, 0.0)


# --- Tests: PrimeVul VD-S ----------------------------------------------------


def test_vd_s_undefined_when_fpr_exceeds_target() -> None:
    """Achieved FPR 0.5 > default target 0.005 -> VD-S is None, FPR surfaced."""
    res = score(*_fixture())
    assert res.vd_s is None
    assert _approx(res.vd_s_achieved_fpr, 0.5)
    assert res.vd_s_fpr_target == 0.005


def test_vd_s_defined_when_fpr_within_target() -> None:
    """With no false positives, FPR=0 <= target -> VD-S = FNR = 1 - recall."""
    # Two vuln (one caught, one missed) and one secure correctly cleared.
    dataset = [
        _entry("v1", "vuln", "high"),
        _entry("v2", "vuln", "high"),
        _entry("s1", "secure", "high", variant="patched"),
    ]
    predictions = [
        _pred("v1", "vuln", band="high"),
        _pred("v2", "secure", band="high"),
        _pred("s1", "secure", band="high"),
    ]
    res = score(dataset, predictions)
    assert _approx(res.fp_rate, 0.0)
    assert _approx(res.recall, 0.5)  # 1 of 2 vulns caught
    assert res.vd_s is not None
    assert _approx(res.vd_s, 0.5)  # FNR = 1 - 0.5
    assert _approx(res.vd_s_achieved_fpr, 0.0)


def test_vd_s_custom_target() -> None:
    """A loose FPR target makes the fixture operating point admissible."""
    res = score(*_fixture(), vd_s_fpr_target=0.6)
    # FPR 0.5 <= 0.6 -> VD-S = FNR = 1 - recall(0.5) = 0.5
    assert res.vd_s is not None
    assert _approx(res.vd_s, 0.5)


# --- Tests: pairwise accuracy ------------------------------------------------


def test_pairwise_accuracy() -> None:
    """2 vuln x 2 secure = 4 pairs; only the (v1,s1) pair is fully correct."""
    res = score(*_fixture())
    assert res.pairwise_total == 4  # 2 predicted-vuln entries x 2 predicted-secure
    assert res.pairwise_correct == 1  # v1 correct vuln (1) x s1 correct secure (1)
    assert _approx(res.pairwise_accuracy, 0.25)


def test_pairwise_perfect() -> None:
    """All vuln flagged and all secure cleared -> pairwise accuracy 1.0."""
    dataset = [
        _entry("v1", "vuln", "high"),
        _entry("s1", "secure", "high", variant="patched"),
        _entry("s2", "secure", "medium", variant="patched"),
    ]
    predictions = [
        _pred("v1", "vuln", band="high"),
        _pred("s1", "secure", band="high"),
        _pred("s2", "secure", band="medium"),
    ]
    res = score(dataset, predictions)
    assert res.pairwise_total == 2  # 1 vuln x 2 secure
    assert res.pairwise_correct == 2
    assert _approx(res.pairwise_accuracy, 1.0)


# --- Tests: severity calibration (both ways) ---------------------------------


def test_calibration_both_ways() -> None:
    """Inflation and deflation are separate non-negative magnitudes.

    From the fixture: inflation_sum=4.5, deflation_sum=6.0 over 5 entries.
    """
    res = score(*_fixture())
    assert res.calibration_n == 5
    assert _approx(res.inflation_mae, 0.9)  # 4.5 / 5
    assert _approx(res.deflation_mae, 1.2)  # 6.0 / 5
    assert _approx(res.signed_mean_error, -0.3)  # (4.5 - 6.0) / 5


def test_calibration_pure_inflation() -> None:
    """A single over-rating: predicted critical(9.5) vs expected low(2)."""
    dataset = [_entry("v1", "vuln", "low")]
    predictions = [_pred("v1", "vuln", band="critical")]
    res = score(dataset, predictions)
    assert res.calibration_n == 1
    assert _approx(res.inflation_mae, 7.5)  # 9.5 - 2.0
    assert _approx(res.deflation_mae, 0.0)
    assert _approx(res.signed_mean_error, 7.5)


def test_calibration_pure_deflation() -> None:
    """A single under-rating: predicted low(2) vs expected critical(9.5)."""
    dataset = [_entry("v1", "vuln", "critical")]
    predictions = [_pred("v1", "vuln", band="low")]
    res = score(dataset, predictions)
    assert res.calibration_n == 1
    assert _approx(res.inflation_mae, 0.0)
    assert _approx(res.deflation_mae, 7.5)  # 9.5 - 2.0
    assert _approx(res.signed_mean_error, -7.5)


def test_calibration_numeric_score_overrides_band() -> None:
    """A numeric predicted_cvss_score takes precedence over the band midpoint."""
    # expected high -> 8.0; predicted numeric 8.4 even though band says 'low'.
    dataset = [_entry("v1", "vuln", "high")]
    predictions = [_pred("v1", "vuln", band="low", score_value=8.4)]
    res = score(dataset, predictions)
    assert res.calibration_n == 1
    # diff = 8.4 - 8.0 = +0.4 (small inflation), band 'low' ignored.
    assert _approx(res.inflation_mae, 0.4)
    assert _approx(res.deflation_mae, 0.0)
    assert _approx(res.signed_mean_error, 0.4)


def test_calibration_skips_entry_without_predicted_score() -> None:
    """An entry whose prediction has neither band nor numeric is skipped."""
    dataset = [
        _entry("v1", "vuln", "high"),
        _entry("v2", "vuln", "high"),
    ]
    predictions = [
        _pred("v1", "vuln", band=None, score_value=None),  # no severity info
        _pred("v2", "vuln", band="high"),  # contributes diff 0
    ]
    res = score(dataset, predictions)
    assert res.calibration_n == 1  # only v2 contributes
    assert _approx(res.inflation_mae, 0.0)
    assert _approx(res.deflation_mae, 0.0)
    assert _approx(res.signed_mean_error, 0.0)


def test_band_scores_constant() -> None:
    """The representative band scores are the documented values."""
    assert BAND_SCORES == {
        "none": 0.0,
        "low": 2.0,
        "medium": 5.0,
        "high": 8.0,
        "critical": 9.5,
    }


# --- Tests: to_metrics_dict & loop-compatible scorer_fn ----------------------


#: The full, fixed key set produced by ScoreResult.to_metrics_dict().
_EXPECTED_METRIC_KEYS = {
    "tp",
    "fp",
    "tn",
    "fn",
    "recall",
    "precision",
    "specificity",
    "fp_rate",
    "youden_j",
    "vd_s",
    "vd_s_achieved_fpr",
    "pairwise_accuracy",
    "pairwise_total",
    "pairwise_correct",
    "inflation_mae",
    "deflation_mae",
    "signed_mean_error",
    "calibration_n",
    "n_entries",
    "n_predictions",
    "n_matched",
    "n_unmatched_predictions",
    "n_missing_predictions",
    "n_excluded_ground_truth",
}


def test_to_metrics_dict_keys_and_all_float() -> None:
    """to_metrics_dict has the fixed expected key set, every value a float."""
    res = score(*_fixture())
    flat = res.to_metrics_dict()
    assert set(flat) == _EXPECTED_METRIC_KEYS
    assert all(isinstance(v, float) for v in flat.values())
    # The fixed key set is data-independent: a different run yields the same keys.
    assert set(score([], []).to_metrics_dict()) == _EXPECTED_METRIC_KEYS


def test_to_metrics_dict_flattens_numeric_values() -> None:
    """Counts are floated and rates carried through from the hand-built fixture."""
    flat = score(*_fixture()).to_metrics_dict()
    assert flat["tp"] == 1.0
    assert flat["fp"] == 1.0
    assert flat["tn"] == 1.0
    assert flat["fn"] == 1.0
    assert _approx(flat["recall"], 0.5)
    assert _approx(flat["precision"], 0.5)
    assert _approx(flat["specificity"], 0.5)
    assert _approx(flat["fp_rate"], 0.5)
    assert _approx(flat["youden_j"], 0.0)
    assert _approx(flat["inflation_mae"], 0.9)
    assert _approx(flat["deflation_mae"], 1.2)
    assert _approx(flat["signed_mean_error"], -0.3)
    assert flat["calibration_n"] == 5.0
    assert flat["n_excluded_ground_truth"] == 2.0


def test_to_metrics_dict_maps_none_rates_to_zero() -> None:
    """Undefined (None) rates flatten to 0.0 per the documented convention.

    Empty inputs leave every rate undefined; each must surface as 0.0 in the
    flat map, while the (defined) calibration magnitudes are already 0.0.
    """
    flat = score([], []).to_metrics_dict()
    for key in (
        "recall",
        "precision",
        "specificity",
        "fp_rate",
        "youden_j",
        "vd_s",
        "vd_s_achieved_fpr",
        "pairwise_accuracy",
    ):
        assert flat[key] == 0.0, key
    # And no None leaked into the flattened map.
    assert all(v is not None for v in flat.values())


def test_scorer_fn_matches_to_metrics_dict() -> None:
    """The module-level scorer_fn equals score(...).to_metrics_dict()."""
    dataset, predictions = _fixture()
    assert scorer_fn(dataset, predictions) == score(dataset, predictions).to_metrics_dict()


def test_scorer_fn_plugs_into_run_delta_without_shim() -> None:
    """scorer_fn satisfies loop.ScorerFn and drives run_delta directly.

    No caller-written shim: scorer_fn is handed straight to run_delta. A naive
    adapter that clears the true vuln vs a method adapter that flags it yields a
    positive recall delta, proving the flattened metrics difference correctly.
    """
    dataset = [
        _entry("v1", "vuln", "high"),
        _entry("s1", "secure", "high", variant="patched"),
    ]

    def predict_fn(entry: BenchEntry, raw: str) -> Prediction:
        return _pred(entry.finding_id, raw.strip().lower())

    naive = StubAdapter(
        {
            "no require_role() before dispatch": "secure",  # misses the vuln
        },
        default="secure",
    )
    method = StubAdapter(lambda p: "vuln" if "no require_role" in p else "secure")

    result = run_delta(dataset, naive, method, predict_fn, scorer_fn)

    # Naive cleared the vuln (recall 0); method caught it (recall 1) -> delta +1.
    assert result.naive_metrics["recall"] == 0.0
    assert result.method_metrics["recall"] == 1.0
    assert result.delta["recall"] == 1.0
    # Keys line up across both passes (signed_delta would have raised otherwise).
    assert set(result.delta) == _EXPECTED_METRIC_KEYS


# --- Tests: edge cases & guards ----------------------------------------------


def test_empty_inputs() -> None:
    """Empty dataset and predictions yield None rates and zero magnitudes."""
    res = score([], [])
    assert isinstance(res, ScoreResult)
    assert (res.tp, res.fp, res.tn, res.fn) == (0, 0, 0, 0)
    assert res.recall is None
    assert res.precision is None
    assert res.specificity is None
    assert res.fp_rate is None
    assert res.youden_j is None
    assert res.vd_s is None
    assert res.vd_s_achieved_fpr is None
    assert res.pairwise_accuracy is None
    assert res.pairwise_total == 0
    assert res.calibration_n == 0
    assert res.inflation_mae == 0.0
    assert res.deflation_mae == 0.0
    assert res.signed_mean_error == 0.0


def test_no_negatives_specificity_none() -> None:
    """With no secure entries, specificity/fp_rate/youden_j are None."""
    dataset = [_entry("v1", "vuln", "high")]
    predictions = [_pred("v1", "vuln", band="high")]
    res = score(dataset, predictions)
    assert _approx(res.recall, 1.0)
    assert res.specificity is None
    assert res.fp_rate is None
    assert res.youden_j is None
    assert res.vd_s is None  # cannot establish an FPR operating point


def test_duplicate_dataset_finding_id_raises() -> None:
    """A duplicated finding_id in the dataset raises ValueError."""
    dataset = [_entry("v1", "vuln", "high"), _entry("v1", "secure", "high")]
    try:
        score(dataset, [])
    except ValueError as exc:
        assert "duplicate finding_id in dataset" in str(exc)
        return
    raise AssertionError("expected ValueError for duplicate dataset finding_id")


def test_duplicate_prediction_finding_id_raises() -> None:
    """A duplicated finding_id in predictions raises ValueError."""
    predictions = [_pred("v1", "vuln"), _pred("v1", "secure")]
    try:
        score([], predictions)
    except ValueError as exc:
        assert "duplicate finding_id in predictions" in str(exc)
        return
    raise AssertionError("expected ValueError for duplicate prediction finding_id")


def test_result_is_frozen() -> None:
    """ScoreResult is immutable (frozen dataclass)."""
    res = score(*_fixture())
    try:
        res.tp = 99  # type: ignore[misc]
    except Exception:
        return
    raise AssertionError("expected ScoreResult to be frozen/immutable")


# --- dual-run harness --------------------------------------------------------


def _run_all() -> int:
    """Run every test_* function; print PASS/FAIL; return process exit code."""
    tests = [
        (name, obj)
        for name, obj in sorted(globals().items())
        if name.startswith("test_") and callable(obj)
    ]
    failures = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - test harness reports all
            failures += 1
            print(f"FAIL: {name}: {type(exc).__name__}: {exc}")
        else:
            print(f"PASS: {name}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
