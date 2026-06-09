"""Pure, deterministic scoring for the sota_bench benchmark.

This module is STDLIB-ONLY. It takes the labeled dataset (a list of
:class:`~sota_bench.schema.BenchEntry`) plus a list of model
:class:`~sota_bench.schema.Prediction` records, matches them by
``finding_id``, and computes a fixed set of detection, ranking, and
severity-calibration metrics. There is NO LLM-as-judge anywhere: every metric
is a closed-form function of the labels and predictions.

Detection metrics treat ``ground_truth == "vuln"`` as the positive class and
``ground_truth == "secure"`` as the negative class. Entries with any other
ground truth (``"oos"``, ``"wontfix"``) are excluded from detection scoring.

Severity calibration is reported BOTH WAYS: over-rating (inflation) and
under-rating (deflation) are kept as separate non-negative magnitudes so a
model that systematically over- or under-states severity cannot hide behind a
symmetric mean that cancels to zero.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from sota_bench.schema import BenchEntry, Prediction

__all__ = [
    "BAND_SCORES",
    "DEFAULT_VD_S_FPR_TARGET",
    "ScoreResult",
    "score",
    "scorer_fn",
]

# --- Band <-> representative-score mapping -----------------------------------

#: Representative CVSS base score for each severity band. Used for calibration
#: when a numeric ``predicted_cvss_score`` is not supplied. The values are the
#: conventional midpoints of the CVSS v3.1 qualitative ranges, with ``none``
#: pinned at 0.0 and ``critical`` at 9.5.
BAND_SCORES: Final[dict[str, float]] = {
    "none": 0.0,
    "low": 2.0,
    "medium": 5.0,
    "high": 8.0,
    "critical": 9.5,
}

#: Default operating-point cap on false-positive rate for PrimeVul VD-S.
DEFAULT_VD_S_FPR_TARGET: Final[float] = 0.005


# --- Result record -----------------------------------------------------------


@dataclass(frozen=True)
class ScoreResult:
    """Immutable bundle of all computed metrics.

    Detection counts (``tp``/``fp``/``tn``/``fn``) are over the matched subset
    whose ground truth is ``vuln`` (positive) or ``secure`` (negative). Items
    with ground truth ``oos``/``wontfix``, and any prediction with no matching
    entry, are excluded from detection metrics and counted separately.
    """

    # Confusion matrix over {vuln, secure} entries that had a prediction.
    tp: int
    fp: int
    tn: int
    fn: int

    # Detection rates. ``None`` when the relevant denominator is zero.
    recall: float | None  # TP / (TP + FN)  (sensitivity)
    precision: float | None  # TP / (TP + FP)
    specificity: float | None  # TN / (TN + FP)
    fp_rate: float | None  # FP / (FP + TN)
    youden_j: float | None  # sensitivity + specificity - 1

    # PrimeVul VD-S: false-negative rate at an FPR <= target operating point.
    vd_s: float | None
    vd_s_fpr_target: float
    vd_s_achieved_fpr: float | None

    # Pairwise accuracy over all (vuln, secure) entry pairs.
    pairwise_accuracy: float | None
    pairwise_total: int
    pairwise_correct: int

    # Severity calibration, both directions kept separate and non-negative.
    inflation_mae: float  # mean over-rating magnitude (pred > actual)
    deflation_mae: float  # mean under-rating magnitude (pred < actual)
    signed_mean_error: float  # mean signed error (pred - actual)
    calibration_n: int  # number of entries that contributed to calibration

    # Bookkeeping for transparency.
    n_entries: int  # total dataset entries
    n_predictions: int  # total predictions supplied
    n_matched: int  # predictions matched to an entry
    n_unmatched_predictions: int  # predictions with no matching entry
    n_missing_predictions: int  # in-scope entries with no prediction
    n_excluded_ground_truth: int  # entries excluded (oos/wontfix)

    def to_metrics_dict(self) -> dict[str, float]:
        """Flatten every numeric metric into a stable, all-``float`` map.

        This is the bridge between the rich :class:`ScoreResult` and the flat
        ``dict[str, float]`` that :data:`sota_bench.loop.ScorerFn` requires, so a
        real scorer plugs into :func:`sota_bench.loop.run_delta` without a
        caller-written shim. The key set is fixed and identical regardless of the
        data, which is what lets :func:`sota_bench.loop.signed_delta` difference
        two runs key-for-key.

        None-handling convention: the optional detection/ranking rates
        (``recall``, ``precision``, ``specificity``, ``fp_rate``, ``youden_j``,
        ``vd_s``, ``vd_s_achieved_fpr``, ``pairwise_accuracy``) are ``None`` only
        when their denominator is empty — i.e. the metric is *undefined* for this
        run, not measured-as-zero. For the purpose of a flat numeric delta we map
        every such ``None`` to ``0.0``. This is a deliberate, lossy flattening:
        an undefined rate and a genuinely-zero rate both surface as ``0.0`` here,
        so callers that must distinguish the two should read the structured
        :class:`ScoreResult` fields directly rather than this map.

        Counts and the always-defined calibration magnitudes are passed through
        as floats unchanged. ``vd_s_fpr_target`` (an input parameter, not a
        measured metric) is intentionally excluded.

        Returns:
            A ``dict[str, float]`` with every value a ``float`` (no ``None``).
        """

        def _rate(value: float | None) -> float:
            """Map an undefined (``None``) rate to ``0.0`` per the convention."""
            return 0.0 if value is None else value

        return {
            # Confusion-matrix counts.
            "tp": float(self.tp),
            "fp": float(self.fp),
            "tn": float(self.tn),
            "fn": float(self.fn),
            # Detection / ranking rates (None -> 0.0).
            "recall": _rate(self.recall),
            "precision": _rate(self.precision),
            "specificity": _rate(self.specificity),
            "fp_rate": _rate(self.fp_rate),
            "youden_j": _rate(self.youden_j),
            "vd_s": _rate(self.vd_s),
            "vd_s_achieved_fpr": _rate(self.vd_s_achieved_fpr),
            "pairwise_accuracy": _rate(self.pairwise_accuracy),
            "pairwise_total": float(self.pairwise_total),
            "pairwise_correct": float(self.pairwise_correct),
            # Calibration magnitudes (always defined; 0.0 when no contributors).
            "inflation_mae": self.inflation_mae,
            "deflation_mae": self.deflation_mae,
            "signed_mean_error": self.signed_mean_error,
            "calibration_n": float(self.calibration_n),
            # Bookkeeping counts.
            "n_entries": float(self.n_entries),
            "n_predictions": float(self.n_predictions),
            "n_matched": float(self.n_matched),
            "n_unmatched_predictions": float(self.n_unmatched_predictions),
            "n_missing_predictions": float(self.n_missing_predictions),
            "n_excluded_ground_truth": float(self.n_excluded_ground_truth),
        }


# --- Helpers -----------------------------------------------------------------


def _safe_ratio(numerator: int, denominator: int) -> float | None:
    """Return ``numerator / denominator`` or ``None`` when denominator is 0."""
    if denominator == 0:
        return None
    return numerator / denominator


def _representative_score(band: str | None, numeric: float | None) -> float | None:
    """Resolve a calibration score from a numeric value, else a band midpoint.

    A supplied numeric ``predicted_cvss_score`` takes precedence. Otherwise the
    band is mapped via :data:`BAND_SCORES`. Returns ``None`` when neither a
    numeric score nor a recognized band is available.
    """
    if numeric is not None:
        return numeric
    if band is not None and band in BAND_SCORES:
        return BAND_SCORES[band]
    return None


# --- Public entry point ------------------------------------------------------


def score(
    dataset: list[BenchEntry],
    predictions: list[Prediction],
    *,
    vd_s_fpr_target: float = DEFAULT_VD_S_FPR_TARGET,
) -> ScoreResult:
    """Score ``predictions`` against the labeled ``dataset``.

    Predictions are matched to entries by ``finding_id``. Detection metrics use
    the ``vuln``/``secure`` subset only. Severity calibration uses every matched
    entry for which both an expected and a predicted score can be resolved.

    Args:
        dataset: The ground-truth benchmark entries.
        predictions: Model outputs to score; matched by ``finding_id``.
        vd_s_fpr_target: The FPR cap defining the VD-S operating point.

    Returns:
        A :class:`ScoreResult` with all metrics.

    Raises:
        ValueError: If a ``finding_id`` is duplicated within ``dataset`` or
            within ``predictions`` (matching would otherwise be ambiguous).
    """
    entry_by_id: dict[str, BenchEntry] = {}
    for entry in dataset:
        if entry.finding_id in entry_by_id:
            raise ValueError(f"duplicate finding_id in dataset: {entry.finding_id!r}")
        entry_by_id[entry.finding_id] = entry

    pred_by_id: dict[str, Prediction] = {}
    for pred in predictions:
        if pred.finding_id in pred_by_id:
            raise ValueError(f"duplicate finding_id in predictions: {pred.finding_id!r}")
        pred_by_id[pred.finding_id] = pred

    n_unmatched_predictions = sum(1 for pid in pred_by_id if pid not in entry_by_id)

    # --- Detection confusion matrix over {vuln, secure} -----------------------
    tp = fp = tn = fn = 0
    n_excluded_ground_truth = 0
    n_missing_predictions = 0
    # Track per-entry predicted-positive flags for pairwise accuracy.
    vuln_correct: list[bool] = []  # predicted "vuln" for a vuln entry?
    secure_correct: list[bool] = []  # predicted "secure" for a secure entry?

    for entry in dataset:
        gt = entry.ground_truth
        if gt not in ("vuln", "secure"):
            n_excluded_ground_truth += 1
            continue
        pred = pred_by_id.get(entry.finding_id)
        if pred is None:
            n_missing_predictions += 1
            continue
        predicted_vuln = pred.predicted_label == "vuln"
        if gt == "vuln":
            if predicted_vuln:
                tp += 1
            else:
                fn += 1
            vuln_correct.append(predicted_vuln)
        else:  # gt == "secure"
            if predicted_vuln:
                fp += 1
            else:
                tn += 1
            secure_correct.append(not predicted_vuln)

    recall = _safe_ratio(tp, tp + fn)
    precision = _safe_ratio(tp, tp + fp)
    specificity = _safe_ratio(tn, tn + fp)
    fp_rate = _safe_ratio(fp, fp + tn)

    youden_j: float | None
    if recall is None or specificity is None:
        youden_j = None
    else:
        youden_j = recall + specificity - 1.0

    # --- PrimeVul VD-S --------------------------------------------------------
    # Labels are discrete, so there is a single achieved operating point. VD-S
    # is the false-negative rate (1 - recall) iff the achieved FPR is within the
    # target; otherwise it is undefined and we surface the achieved FPR instead.
    vd_s_achieved_fpr = fp_rate
    vd_s: float | None
    if vd_s_achieved_fpr is None or recall is None:
        vd_s = None
    elif vd_s_achieved_fpr <= vd_s_fpr_target:
        vd_s = 1.0 - recall  # false-negative rate at this operating point
    else:
        vd_s = None  # operating point does not meet the FPR cap

    # --- Pairwise accuracy ----------------------------------------------------
    # Over the cross product of (vuln entries with a prediction) x (secure
    # entries with a prediction): a pair is correct iff the vuln side was
    # predicted vuln AND the secure side was predicted secure.
    n_vuln = len(vuln_correct)
    n_secure = len(secure_correct)
    pairwise_total = n_vuln * n_secure
    n_vuln_hit = sum(1 for ok in vuln_correct if ok)
    n_secure_hit = sum(1 for ok in secure_correct if ok)
    pairwise_correct = n_vuln_hit * n_secure_hit
    pairwise_accuracy = _safe_ratio(pairwise_correct, pairwise_total)

    # --- Severity calibration (both ways) -------------------------------------
    inflation_sum = 0.0
    deflation_sum = 0.0
    signed_sum = 0.0
    calibration_n = 0
    for entry in dataset:
        pred = pred_by_id.get(entry.finding_id)
        if pred is None:
            continue
        expected = _representative_score(entry.expected_cvss_band, None)
        predicted = _representative_score(pred.predicted_cvss_band, pred.predicted_cvss_score)
        if expected is None or predicted is None:
            continue
        diff = predicted - expected  # positive => over-rating (inflation)
        signed_sum += diff
        if diff > 0:
            inflation_sum += diff
        elif diff < 0:
            deflation_sum += -diff
        calibration_n += 1

    if calibration_n == 0:
        inflation_mae = 0.0
        deflation_mae = 0.0
        signed_mean_error = 0.0
    else:
        inflation_mae = inflation_sum / calibration_n
        deflation_mae = deflation_sum / calibration_n
        signed_mean_error = signed_sum / calibration_n

    n_matched = len(pred_by_id) - n_unmatched_predictions

    return ScoreResult(
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        recall=recall,
        precision=precision,
        specificity=specificity,
        fp_rate=fp_rate,
        youden_j=youden_j,
        vd_s=vd_s,
        vd_s_fpr_target=vd_s_fpr_target,
        vd_s_achieved_fpr=vd_s_achieved_fpr,
        pairwise_accuracy=pairwise_accuracy,
        pairwise_total=pairwise_total,
        pairwise_correct=pairwise_correct,
        inflation_mae=inflation_mae,
        deflation_mae=deflation_mae,
        signed_mean_error=signed_mean_error,
        calibration_n=calibration_n,
        n_entries=len(dataset),
        n_predictions=len(predictions),
        n_matched=n_matched,
        n_unmatched_predictions=n_unmatched_predictions,
        n_missing_predictions=n_missing_predictions,
        n_excluded_ground_truth=n_excluded_ground_truth,
    )


# --- Loop-compatible adapter -------------------------------------------------


def scorer_fn(dataset: Sequence[BenchEntry], predictions: Sequence[Prediction]) -> dict[str, float]:
    """Score ``predictions`` and flatten the result to a ``dict[str, float]``.

    This is the real scorer packaged to match :data:`sota_bench.loop.ScorerFn`
    (``Callable[[Sequence[BenchEntry], Sequence[Prediction]], dict[str, float]]``)
    so it can be handed straight to :func:`sota_bench.loop.run_delta` with no
    caller-written shim. It is exactly ``score(...).to_metrics_dict()`` at the
    default VD-S operating point; callers needing a non-default
    ``vd_s_fpr_target`` should call :func:`score` and ``to_metrics_dict`` (or
    wrap with ``functools.partial``) themselves.

    Args:
        dataset: The ground-truth benchmark entries.
        predictions: Model outputs to score; matched by ``finding_id``.

    Returns:
        The flat numeric metric map (see :meth:`ScoreResult.to_metrics_dict`).
    """
    return score(list(dataset), list(predictions)).to_metrics_dict()
