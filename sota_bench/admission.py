"""Slice-admission gate for sota_bench (the anti-padding lock).

This module is STDLIB-ONLY and contains NO LLM-as-judge. It decides whether a
new corpus slice / vertical may be registered, so the benchmark grows only where
it measures something worth measuring.

The benchmark's value lives in classes where a naive single frontier-model call
is WEAK and the method scaffold has headroom (the "decode" / forcing-function
region). Classes a naive call already aces (raw authz detection, where naive
recall was 0.833 and beat the scaffold) are commoditized: adding more of them
dilutes the one signal worth publishing. So a slice is admissible only if:

1. its naive baseline is committed alongside it (you cannot register a slice
   without the baseline that proves it is naive-weak);
2. the naive baseline is WEAK on the gating metric (``naive[metric] < max``),
   i.e. there is measurable headroom;
3. the slice's metric set is ADDITIVE over any prior pinned baseline it will be
   compared against (new metrics are allowed; dropping or renaming a published
   metric key is not); and
4. the gating metric is computed over ENOUGH items (``sample_n >= MIN_SLICE_N``)
   for naive-weakness to be a MEASURED RATE rather than an anecdote. A naive
   recall of 0 over a single positive example is "1/1 naive-miss": suggestive,
   not a calibrated rate. Without this floor a 1-row seed mechanically passes
   conditions 1-3 (disqualifier #6: n=1-treated-as-a-rate). The sample count is
   fail-safe: when it is not supplied the slice is REJECTED, never admitted on a
   missing signal (mirrors the L3/L6 provenance fail-safe).

The gating metric and threshold are pre-registered in ``PROTOCOL.md`` (L4); the
defaults here (recall < 0.5, MIN_SLICE_N = 10) are pinned and change only via a
new ``format_version``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final

__all__ = [
    "DEFAULT_NAIVE_WEAKNESS_METRIC",
    "DEFAULT_NAIVE_WEAKNESS_MAX",
    "MIN_SLICE_N",
    "AdmissionReport",
    "assess_slice_admission",
]

#: The metric whose naive value gates admission. Lower means weaker-naive, i.e.
#: more headroom for the method (recall is the canonical detection rate).
DEFAULT_NAIVE_WEAKNESS_METRIC: Final[str] = "recall"

#: Upper bound on the naive gating metric for a slice to be admissible. A slice
#: whose naive value is at or above this is treated as commoditized and rejected.
DEFAULT_NAIVE_WEAKNESS_MAX: Final[float] = 0.5

#: Minimum number of scored items the gating metric must be computed over for a
#: slice's naive-weakness to count as a MEASURED RATE rather than an anecdote
#: (the anti-``n=1`` floor). For the default ``recall`` metric this is the count
#: of positive / ``vuln`` examples the naive recall was computed over: a recall
#: of 0 over a single positive is "1/1 naive-miss", suggestive but not a
#: calibrated rate (disqualifier #6). Pinned at 10 to align with
#: ``stats.MIN_DISCORDANT_PAIRS`` (the significance floor) and the pre-registered
#: "n >= ~10" calibrated-rate threshold; like the other L4 bounds it changes
#: ONLY via a new ``format_version``.
MIN_SLICE_N: Final[int] = 10


@dataclass(frozen=True)
class AdmissionReport:
    """The outcome of assessing a candidate slice for registration."""

    admitted: bool
    baseline_present: bool
    naive_weak: bool
    metrics_additive: bool
    sample_sufficient: bool
    metric: str
    naive_value: float | None
    max_value: float
    sample_n: int | None
    min_slice_n: int
    dropped_metric_keys: tuple[str, ...]
    reasons: tuple[str, ...]  # human-readable failure reasons (empty if admitted)


def assess_slice_admission(
    naive_metrics: Mapping[str, float],
    *,
    sample_n: int | None = None,
    prior_metric_keys: Iterable[str] | None = None,
    metric: str = DEFAULT_NAIVE_WEAKNESS_METRIC,
    max_value: float = DEFAULT_NAIVE_WEAKNESS_MAX,
    min_slice_n: int = MIN_SLICE_N,
    raise_on_reject: bool = False,
) -> AdmissionReport:
    """Decide whether a new slice may be registered.

    Args:
        naive_metrics: The slice's naive-baseline metric map (the proof of
            naive-weakness). Must contain ``metric``.
        sample_n: The number of scored items the gating ``metric`` is computed
            over (for the default ``recall`` metric, the count of positive /
            ``vuln`` examples). Must be ``>= min_slice_n`` for the naive-weakness
            to count as a measured rate. **Fail-safe:** when ``None`` (not
            supplied) the slice is REJECTED, never admitted on a missing signal.
        prior_metric_keys: The metric key-set of a prior pinned baseline the new
            slice will be compared against. When given, the new slice's metric
            keys must be a superset (additive-only). When ``None``, the additive
            check is skipped (first slice).
        metric: The gating metric (lower = weaker naive = more headroom).
        max_value: Strict upper bound; the naive value must be ``< max_value``.
        min_slice_n: Minimum ``sample_n`` for admission (the anti-anecdote floor).
        raise_on_reject: When True, raise ``ValueError`` if the slice is rejected.

    Returns:
        An :class:`AdmissionReport`.

    Raises:
        ValueError: If ``raise_on_reject`` is set and the slice is not admitted.
    """
    reasons: list[str] = []

    baseline_present = bool(naive_metrics) and metric in naive_metrics
    naive_value = naive_metrics[metric] if baseline_present else None
    if not baseline_present:
        reasons.append(f"naive baseline missing or has no {metric!r} metric")

    if naive_value is None:
        naive_weak = False
    else:
        naive_weak = naive_value < max_value
        if not naive_weak:
            reasons.append(
                f"naive is not weak: {metric}={naive_value:.4g} >= threshold "
                f"{max_value:.4g} (commoditized; adding it would dilute the signal)"
            )

    if prior_metric_keys is None:
        dropped: tuple[str, ...] = ()
        metrics_additive = True
    else:
        dropped = tuple(sorted(set(prior_metric_keys) - set(naive_metrics.keys())))
        metrics_additive = not dropped
        if dropped:
            reasons.append(
                f"metric set is not additive: prior key(s) dropped or renamed {list(dropped)}"
            )

    if sample_n is None:
        sample_sufficient = False
        reasons.append(
            f"slice sample size not provided; fail-safe reject (a missing sample "
            f"count is never read as sufficient; need sample_n >= {min_slice_n})"
        )
    elif sample_n < min_slice_n:
        sample_sufficient = False
        reasons.append(
            f"underpowered slice: n={sample_n} < MIN_SLICE_N={min_slice_n} "
            f"(naive-weakness over n<{min_slice_n} items is an anecdote, not a "
            f"measured rate; disqualifier #6: n=1-treated-as-a-rate)"
        )
    else:
        sample_sufficient = True

    admitted = baseline_present and naive_weak and metrics_additive and sample_sufficient

    if raise_on_reject and not admitted:
        raise ValueError("slice rejected: " + "; ".join(reasons))

    return AdmissionReport(
        admitted=admitted,
        baseline_present=baseline_present,
        naive_weak=naive_weak,
        metrics_additive=metrics_additive,
        sample_sufficient=sample_sufficient,
        metric=metric,
        naive_value=naive_value,
        max_value=max_value,
        sample_n=sample_n,
        min_slice_n=min_slice_n,
        dropped_metric_keys=dropped,
        reasons=tuple(reasons),
    )
