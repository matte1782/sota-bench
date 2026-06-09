"""Statistical-honesty layer for the sota_bench delta loop.

This module is STDLIB-ONLY and contains NO LLM-as-judge: every function is a
closed-form statistic over the same {vuln, secure} labels the scorer uses.

The benchmark's headline asset is a signed ``method - naive`` delta on a SMALL
corpus. On small N a point delta is indistinguishable from noise, so this layer
makes the honesty structural rather than a matter of operator discipline:

* :func:`paired_correctness` builds the 2x2 table of *paired* per-finding
  correctness (method vs naive on the SAME items), mirroring the scorer's exact
  in-scope / correctness rules (``oos``/``wontfix`` and findings missing a
  prediction are excluded).
* :func:`mcnemar_exact` is the textbook-correct paired test for two systems run
  once on the same items (Dietterich 1998): a two-sided EXACT-BINOMIAL test on
  the discordant pairs. The exact form is required because below ~25 discordant
  pairs the chi-squared approximation is invalid.
* :func:`assess_power` encodes the disqualifier "n=1 is not a rate": below a
  pre-registered floor of discordant pairs no significance may be claimed.
* :func:`paired_significance` combines them into a single verdict that is
  ``UNDERPOWERED`` (no claim permitted) until the floor is met.
* :func:`wilson_ci` / :func:`confusion_cis` give small-N-correct confidence
  intervals (Wilson score interval, preferred over the bootstrap, which is
  anti-conservative at n <= 20).
"""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final

from sota_bench.schema import BenchEntry, Prediction

__all__ = [
    "MIN_DISCORDANT_PAIRS",
    "DEFAULT_ALPHA",
    "WILSON_Z_95",
    "CorrectFn",
    "PairedTable",
    "McNemarResult",
    "PowerVerdict",
    "SignificanceVerdict",
    "default_correct",
    "paired_correctness",
    "mcnemar_exact",
    "assess_power",
    "paired_significance",
    "significance_to_dict",
    "wilson_ci",
    "confusion_cis",
]

#: Minimum number of discordant pairs (b + c) required before McNemar can
#: establish significance. Below this the comparison is reported UNDERPOWERED.
#: Ten is the conventional floor for the paired test on small samples.
MIN_DISCORDANT_PAIRS: Final[int] = 10

#: Default significance level for the two-sided test.
DEFAULT_ALPHA: Final[float] = 0.05

#: z critical value for a two-sided 95% Wilson interval.
WILSON_Z_95: Final[float] = 1.959963984540054

#: A predicate deciding whether one prediction is correct for one in-scope entry.
CorrectFn = Callable[[BenchEntry, Prediction], bool]


def default_correct(entry: BenchEntry, prediction: Prediction) -> bool:
    """Return whether ``prediction`` is correct for ``entry``, scorer-identically.

    Mirrors the scorer's binarization exactly: ``ground_truth == "vuln"`` is the
    positive class and ``"secure"`` is the negative class, so a prediction is
    correct iff its ``predicted_label`` agrees with that binarization. This is
    only meaningful for in-scope entries (``ground_truth in {"vuln", "secure"}``).
    """
    predicted_vuln = prediction.predicted_label == "vuln"
    return (entry.ground_truth == "vuln") == predicted_vuln


def _index_predictions(predictions: Sequence[Prediction], *, side: str) -> dict[str, Prediction]:
    """Index predictions by ``finding_id``; raise on a duplicate (scorer parity)."""
    by_id: dict[str, Prediction] = {}
    for pred in predictions:
        if pred.finding_id in by_id:
            raise ValueError(f"duplicate finding_id in {side} predictions: {pred.finding_id!r}")
        by_id[pred.finding_id] = pred
    return by_id


@dataclass(frozen=True)
class PairedTable:
    """The 2x2 table of paired per-finding correctness, method vs naive.

    The four cells partition the in-scope findings that had BOTH a naive and a
    method prediction. McNemar's test depends only on the two discordant cells
    (``naive_only_correct`` and ``method_only_correct``); the concordant cells
    are counted but carry no signal.
    """

    both_correct: int  # a: naive correct AND method correct
    naive_only_correct: int  # b: naive correct, method wrong
    method_only_correct: int  # c: naive wrong, method correct
    both_wrong: int  # d: neither correct
    n_excluded_ground_truth: int  # entries excluded (oos/wontfix)
    n_missing_naive: int  # in-scope entries with no naive prediction
    n_missing_method: int  # in-scope entries with no method prediction

    @property
    def n_scored(self) -> int:
        """Number of in-scope findings with both predictions (a + b + c + d)."""
        return (
            self.both_correct + self.naive_only_correct + self.method_only_correct + self.both_wrong
        )

    @property
    def n_discordant(self) -> int:
        """Number of discordant pairs (b + c) -- the only cells McNemar uses."""
        return self.naive_only_correct + self.method_only_correct


def paired_correctness(
    dataset: Sequence[BenchEntry],
    naive_predictions: Sequence[Prediction],
    method_predictions: Sequence[Prediction],
    *,
    correct_fn: CorrectFn | None = None,
) -> PairedTable:
    """Build the paired-correctness table for method vs naive over ``dataset``.

    A finding contributes to the 2x2 table only when it is in scope
    (``ground_truth in {"vuln", "secure"}``) AND has both a naive and a method
    prediction. ``oos``/``wontfix`` entries and entries missing either prediction
    are excluded and counted separately, exactly as the scorer excludes them.

    Args:
        dataset: The ground-truth benchmark entries.
        naive_predictions: Predictions from the naive single-call adapter.
        method_predictions: Predictions from the method scaffold.
        correct_fn: Optional override of the correctness predicate. Defaults to
            :func:`default_correct` (the scorer's binarization).

    Returns:
        The :class:`PairedTable`.
    """
    correct = correct_fn if correct_fn is not None else default_correct
    naive_by_id = _index_predictions(naive_predictions, side="naive")
    method_by_id = _index_predictions(method_predictions, side="method")

    a = b = c = d = 0
    n_excluded = n_missing_naive = n_missing_method = 0
    for entry in dataset:
        if entry.ground_truth not in ("vuln", "secure"):
            n_excluded += 1
            continue
        naive_pred = naive_by_id.get(entry.finding_id)
        method_pred = method_by_id.get(entry.finding_id)
        if naive_pred is None:
            n_missing_naive += 1
        if method_pred is None:
            n_missing_method += 1
        if naive_pred is None or method_pred is None:
            continue
        naive_ok = correct(entry, naive_pred)
        method_ok = correct(entry, method_pred)
        if naive_ok and method_ok:
            a += 1
        elif naive_ok and not method_ok:
            b += 1
        elif not naive_ok and method_ok:
            c += 1
        else:
            d += 1

    return PairedTable(
        both_correct=a,
        naive_only_correct=b,
        method_only_correct=c,
        both_wrong=d,
        n_excluded_ground_truth=n_excluded,
        n_missing_naive=n_missing_naive,
        n_missing_method=n_missing_method,
    )


@dataclass(frozen=True)
class McNemarResult:
    """The result of a two-sided exact-binomial McNemar test on (b, c)."""

    b: int  # naive_only_correct
    c: int  # method_only_correct
    n_discordant: int
    p_value: float
    favored: str  # "method" | "naive" | "tie"


def mcnemar_exact(b: int, c: int) -> McNemarResult:
    """Two-sided exact-binomial McNemar test on the discordant counts.

    Under the null (method and naive are equally good), each discordant pair is
    an independent coin flip, so the count ``b`` is ``Binomial(n, 0.5)`` with
    ``n = b + c``. The two-sided p-value is ``2 * P(X <= min(b, c))`` capped at
    1.0. With no discordant pairs the test is uninformative and ``p = 1.0``.

    Args:
        b: Pairs where naive was correct and method wrong.
        c: Pairs where naive was wrong and method correct.

    Returns:
        A :class:`McNemarResult` with the p-value and which side it favors.

    Raises:
        ValueError: If ``b`` or ``c`` is negative.
    """
    if b < 0 or c < 0:
        raise ValueError(f"discordant counts must be non-negative, got b={b}, c={c}")
    n = b + c
    if n == 0:
        p_value = 1.0
    else:
        k = min(b, c)
        tail = sum(math.comb(n, i) for i in range(k + 1)) * (0.5**n)
        p_value = min(1.0, 2.0 * tail)
    if c > b:
        favored = "method"
    elif b > c:
        favored = "naive"
    else:
        favored = "tie"
    return McNemarResult(b=b, c=c, n_discordant=n, p_value=p_value, favored=favored)


@dataclass(frozen=True)
class PowerVerdict:
    """Whether the paired comparison has enough discordant pairs to claim anything."""

    is_powered: bool
    n_discordant: int
    n_scored: int
    min_discordant: int
    reason: str


def assess_power(table: PairedTable, *, min_discordant: int = MIN_DISCORDANT_PAIRS) -> PowerVerdict:
    """Decide whether ``table`` clears the discordant-pair floor for significance.

    This is the structural form of the disqualifier "n=1 is not a rate": below
    ``min_discordant`` discordant pairs, McNemar cannot establish significance at
    any effect size, so the comparison is declared underpowered.

    Args:
        table: The paired-correctness table.
        min_discordant: The pre-registered floor of discordant pairs.

    Returns:
        A :class:`PowerVerdict`.
    """
    n_discordant = table.n_discordant
    if n_discordant < min_discordant:
        return PowerVerdict(
            is_powered=False,
            n_discordant=n_discordant,
            n_scored=table.n_scored,
            min_discordant=min_discordant,
            reason=(
                f"{n_discordant} discordant pair(s) < {min_discordant} required to "
                "establish significance"
            ),
        )
    return PowerVerdict(
        is_powered=True,
        n_discordant=n_discordant,
        n_scored=table.n_scored,
        min_discordant=min_discordant,
        reason=f"{n_discordant} discordant pairs >= {min_discordant}",
    )


@dataclass(frozen=True)
class SignificanceVerdict:
    """The combined power + significance verdict for a paired comparison.

    When ``powered`` is False the comparison is UNDERPOWERED: ``significant`` is
    ``None`` (no claim permitted), even though the raw McNemar ``p_value`` is
    still recorded for transparency.
    """

    powered: bool
    p_value: float
    significant: bool | None
    favored: str
    n_discordant: int
    n_scored: int
    alpha: float
    summary: str


def paired_significance(
    dataset: Sequence[BenchEntry],
    naive_predictions: Sequence[Prediction],
    method_predictions: Sequence[Prediction],
    *,
    correct_fn: CorrectFn | None = None,
    min_discordant: int = MIN_DISCORDANT_PAIRS,
    alpha: float = DEFAULT_ALPHA,
) -> SignificanceVerdict:
    """Compute the full paired significance verdict (table -> McNemar -> power).

    Args:
        dataset: The ground-truth benchmark entries.
        naive_predictions: Predictions from the naive single-call adapter.
        method_predictions: Predictions from the method scaffold.
        correct_fn: Optional correctness predicate (defaults to scorer parity).
        min_discordant: The pre-registered discordant-pair floor.
        alpha: Two-sided significance level.

    Returns:
        A :class:`SignificanceVerdict`. ``significant`` is ``None`` when the
        comparison is underpowered.
    """
    table = paired_correctness(
        dataset, naive_predictions, method_predictions, correct_fn=correct_fn
    )
    mcnemar = mcnemar_exact(table.naive_only_correct, table.method_only_correct)
    power = assess_power(table, min_discordant=min_discordant)

    if not power.is_powered:
        return SignificanceVerdict(
            powered=False,
            p_value=mcnemar.p_value,
            significant=None,
            favored=mcnemar.favored,
            n_discordant=table.n_discordant,
            n_scored=table.n_scored,
            alpha=alpha,
            summary=f"UNDERPOWERED: {power.reason}; no significance claim permitted",
        )

    significant = mcnemar.p_value < alpha
    label = "significant" if significant else "not significant"
    return SignificanceVerdict(
        powered=True,
        p_value=mcnemar.p_value,
        significant=significant,
        favored=mcnemar.favored,
        n_discordant=table.n_discordant,
        n_scored=table.n_scored,
        alpha=alpha,
        summary=f"{label} (McNemar exact p={mcnemar.p_value:.4g}, favors {mcnemar.favored})",
    )


def significance_to_dict(verdict: SignificanceVerdict) -> dict[str, float]:
    """Flatten a :class:`SignificanceVerdict` to an all-float map for the record.

    Tri-state fields are encoded numerically so the result is JSON-simple and
    can ride inside a pinned ``DeltaResult``:

    * ``significant``: ``1.0`` true, ``0.0`` false, ``-1.0`` undetermined
      (underpowered).
    * ``favored_method``: ``1.0`` method, ``-1.0`` naive, ``0.0`` tie.
    """
    if verdict.significant is None:
        significant = -1.0
    else:
        significant = 1.0 if verdict.significant else 0.0
    favored_method = {"method": 1.0, "naive": -1.0, "tie": 0.0}[verdict.favored]
    return {
        "powered": 1.0 if verdict.powered else 0.0,
        "n_scored": float(verdict.n_scored),
        "n_discordant": float(verdict.n_discordant),
        "mcnemar_p": verdict.p_value,
        "significant": significant,
        "favored_method": favored_method,
        "alpha": verdict.alpha,
    }


def wilson_ci(k: int, n: int, *, z: float = WILSON_Z_95) -> tuple[float, float]:
    """Return the Wilson score confidence interval for ``k`` successes in ``n``.

    The Wilson interval is the recommended small-sample interval for a binomial
    proportion: it stays inside ``[0, 1]`` and has good coverage at small ``n``
    where the normal approximation and the bootstrap are anti-conservative. With
    ``n == 0`` the proportion is undefined and the maximally-uninformative
    interval ``(0.0, 1.0)`` is returned.

    Args:
        k: Number of successes.
        n: Number of trials.
        z: Two-sided critical value (default: 95%).

    Returns:
        A ``(low, high)`` tuple clamped to ``[0, 1]``.

    Raises:
        ValueError: If ``k`` or ``n`` is negative, or ``k > n``.
    """
    if k < 0 or n < 0:
        raise ValueError(f"k and n must be non-negative, got k={k}, n={n}")
    if k > n:
        raise ValueError(f"k must not exceed n, got k={k}, n={n}")
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / denom
    half = (z * math.sqrt((p * (1.0 - p) + z2 / (4.0 * n)) / n)) / denom
    low = max(0.0, center - half)
    high = min(1.0, center + half)
    return (low, high)


def confusion_cis(tp: int, fp: int, tn: int, fn: int) -> dict[str, tuple[float, float]]:
    """Return Wilson 95% CIs for the four core proportion metrics.

    Each rate is a binomial proportion over a known denominator, so a Wilson
    interval applies directly:

    * ``recall`` = TP / (TP + FN)
    * ``precision`` = TP / (TP + FP)
    * ``specificity`` = TN / (TN + FP)
    * ``fp_rate`` = FP / (FP + TN)

    Args:
        tp: True positives.
        fp: False positives.
        tn: True negatives.
        fn: False negatives.

    Returns:
        A map from metric name to a ``(low, high)`` Wilson interval.
    """
    return {
        "recall": wilson_ci(tp, tp + fn),
        "precision": wilson_ci(tp, tp + fp),
        "specificity": wilson_ci(tn, tn + fp),
        "fp_rate": wilson_ci(fp, fp + tn),
    }
