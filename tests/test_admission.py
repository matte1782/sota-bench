"""Tests for the slice-admission gate (sota_bench.admission).

Covers the four admission conditions -- naive baseline present, naive-weak
(headroom), additive-only metric keys, and a sufficient sample (the anti-``n=1``
floor) -- and a real-data check that the actual authz_v1 naive baseline (recall
0.833) is REJECTED as commoditized, structurally confirming that raw authz
detection is the wrong place to grow the bench.

Dual-runnable: works under pytest and as a plain script.
"""

from __future__ import annotations

import json
import os
import sys

# Make the package importable when run as a plain script from anywhere.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from sota_bench.admission import (  # noqa: E402
    DEFAULT_NAIVE_WEAKNESS_MAX,
    MIN_SLICE_N,
    assess_slice_admission,
)

#: A sample count comfortably above the floor, used by tests that isolate a
#: non-sample admission dimension (so they assert full admission cleanly).
_OK_N = MIN_SLICE_N + 2

_BASELINE_PATH = os.path.join(_PKG_ROOT, "datasets", "baseline_authz_v1_2026-06-03.json")


# --- naive-weakness gate ----------------------------------------------------


def test_admit_naive_weak() -> None:
    """A slice that is naive-weak AND adequately sampled is admitted."""
    report = assess_slice_admission({"recall": 0.2}, sample_n=_OK_N)
    assert report.admitted is True
    assert report.naive_weak is True
    assert report.baseline_present is True
    assert report.sample_sufficient is True
    assert report.reasons == ()


def test_reject_commoditized() -> None:
    """A slice where naive already aces detection is rejected as commoditized."""
    report = assess_slice_admission({"recall": 0.83})
    assert report.admitted is False
    assert report.naive_weak is False
    assert any("commoditized" in r for r in report.reasons)


def test_boundary_equal_threshold_rejects() -> None:
    """The bound is strict: naive recall == threshold is not weak enough."""
    report = assess_slice_admission({"recall": DEFAULT_NAIVE_WEAKNESS_MAX})
    assert report.naive_weak is False
    assert report.admitted is False


# --- baseline-present gate --------------------------------------------------


def test_reject_empty_baseline() -> None:
    """An empty naive baseline cannot register a slice."""
    report = assess_slice_admission({})
    assert report.baseline_present is False
    assert report.admitted is False
    assert report.naive_value is None


def test_reject_baseline_without_metric() -> None:
    """A baseline lacking the gating metric is treated as absent."""
    report = assess_slice_admission({"precision": 0.1})
    assert report.baseline_present is False
    assert report.admitted is False


# --- additive-only metrics --------------------------------------------------


def test_additive_metrics_ok() -> None:
    """Adding metrics over the prior key-set is permitted."""
    report = assess_slice_admission(
        {"recall": 0.2, "precision": 0.9}, sample_n=_OK_N, prior_metric_keys={"recall"}
    )
    assert report.metrics_additive is True
    assert report.dropped_metric_keys == ()
    assert report.admitted is True


def test_additive_metrics_violation() -> None:
    """Dropping or renaming a prior metric key fails admission."""
    report = assess_slice_admission({"recall": 0.2}, prior_metric_keys={"recall", "precision"})
    assert report.metrics_additive is False
    assert report.dropped_metric_keys == ("precision",)
    assert report.admitted is False


# --- sample-size floor (the anti-n=1 lock, disqualifier #6) ------------------


def test_reject_single_row_underpowered() -> None:
    """The disqualifier-#6 case: a 1-row slice with PERFECT naive-weakness
    (naive recall 0) is still rejected, because 1/1 naive-miss is an anecdote,
    not a measured rate. This is the exact hole the floor closes."""
    report = assess_slice_admission({"recall": 0.0}, sample_n=1)
    assert report.naive_weak is True  # naive genuinely misses
    assert report.sample_sufficient is False
    assert report.admitted is False
    assert any("disqualifier #6" in r for r in report.reasons)


def test_reject_sample_unknown_failsafe() -> None:
    """A missing sample count is fail-safe rejected, never admitted on absence."""
    report = assess_slice_admission({"recall": 0.2})  # sample_n omitted
    assert report.sample_sufficient is False
    assert report.admitted is False
    assert report.sample_n is None
    assert any("not provided" in r for r in report.reasons)


def test_admit_exactly_at_floor() -> None:
    """Exactly MIN_SLICE_N items clears the sample gate (inclusive bound)."""
    report = assess_slice_admission({"recall": 0.2}, sample_n=MIN_SLICE_N)
    assert report.sample_sufficient is True
    assert report.admitted is True
    assert report.min_slice_n == MIN_SLICE_N


def test_reject_one_below_floor() -> None:
    """One item below MIN_SLICE_N is underpowered and rejected."""
    report = assess_slice_admission({"recall": 0.2}, sample_n=MIN_SLICE_N - 1)
    assert report.sample_sufficient is False
    assert report.admitted is False
    assert any("underpowered" in r for r in report.reasons)


def test_custom_min_slice_n_override() -> None:
    """The floor is configurable (but pinned by default to MIN_SLICE_N)."""
    report = assess_slice_admission({"recall": 0.2}, sample_n=3, min_slice_n=3)
    assert report.sample_sufficient is True
    assert report.admitted is True


# --- configurability + enforcement ------------------------------------------


def test_custom_metric_and_threshold() -> None:
    """The gating metric and bound are configurable."""
    weak = assess_slice_admission(
        {"pairwise_accuracy": 0.55}, sample_n=_OK_N, metric="pairwise_accuracy", max_value=0.6
    )
    assert weak.admitted is True
    strong = assess_slice_admission(
        {"pairwise_accuracy": 0.7}, sample_n=_OK_N, metric="pairwise_accuracy", max_value=0.6
    )
    assert strong.admitted is False


def test_raise_on_reject() -> None:
    """raise_on_reject surfaces a ValueError for a rejected slice."""
    try:
        assess_slice_admission({"recall": 0.9}, raise_on_reject=True)
    except ValueError:
        return
    raise AssertionError("expected ValueError on a rejected slice")


# --- real-data integration --------------------------------------------------


def test_real_authz_baseline_rejected_as_commoditized() -> None:
    """The actual authz_v1 naive baseline (recall 0.833) is rejected.

    This is the structural form of Anchor 1: a naive single call already aces
    raw authz detection, so the gate would bar adding more authz-detection
    slices -- growth must go toward naive-weak classes instead.
    """
    if not os.path.exists(_BASELINE_PATH):
        # The pinned baseline carries a per-entry list naming the embargoed
        # positive findings, so it is intentionally NOT shipped in the public
        # corpus. Skip this real-data check when the file is absent.
        try:
            import pytest

            pytest.skip("pinned baseline not shipped in the public corpus (embargo)")
        except ImportError:
            print("SKIP test_real_authz_baseline_rejected_as_commoditized: baseline absent")
            return
    with open(_BASELINE_PATH, encoding="utf-8") as fh:
        baseline = json.load(fh)
    naive_metrics = baseline["naive_metrics"]
    assert naive_metrics["recall"] > DEFAULT_NAIVE_WEAKNESS_MAX  # sanity: it is strong
    # sample_n above the floor isolates the commoditized rejection (the point of
    # this test) from the sample gate.
    report = assess_slice_admission(naive_metrics, sample_n=_OK_N)
    assert report.admitted is False
    assert report.naive_weak is False
    assert any("commoditized" in r for r in report.reasons)


# --- dual-run harness -------------------------------------------------------


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
