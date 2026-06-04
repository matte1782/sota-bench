"""Tests for sota_bench.cvss: CVSS v3.1 Base score parsing and scoring.

Dual-runnable: works under pytest, and also as a plain script
(``python sota_bench/tests/test_cvss.py``) which runs every test function and
prints a PASS/FAIL summary.

The known-good vectors and their documented Base scores are taken from the
FIRST.org CVSS v3.1 examples and calculator. They exercise scope-unchanged
and scope-changed paths, every metric value at least once, and the v3.1
integer roundup at boundaries.
"""

from __future__ import annotations

import os
import sys
from typing import Any

# Make the package importable when run as a plain script from anywhere.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from sota_bench.cvss import (  # noqa: E402
    base_score,
    check_claimed,
    parse_vector,
    severity_band,
)


def _assert_raises_value_error(fn: Any, *, contains: str | None = None) -> None:
    """Assert that ``fn()`` raises ValueError (optionally with a substring)."""
    try:
        fn()
    except ValueError as exc:
        if contains is not None:
            assert contains in str(exc), (
                f"expected substring {contains!r} in error, got {str(exc)!r}"
            )
        return
    raise AssertionError("expected ValueError, none raised")


def _score(vector: str) -> float:
    """Parse and score a vector in one step."""
    return base_score(parse_vector(vector))


# --- Known official vectors -> documented Base scores -----------------------

#: (vector, documented base score). Scope-unchanged and scope-changed mixed.
_KNOWN: list[tuple[str, float]] = [
    # Full-impact network, no privileges/interaction -> 9.8 (critical).
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    # Confidentiality-only with low privileges -> 6.5 (medium).
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    # Low confidentiality only, no privileges -> 5.3 (medium).
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    # Scope changed, full impact -> 10.0 (critical); exercises 1.08 factor.
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    # Heartbleed (CVE-2014-0160) -> 7.5 (high), conf-only high, scope U.
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    # Local, high AC, requires privileges + UI, scope changed -> 7.5 (high);
    # the 1.08 scope factor lifts a modest exploitability into the high band.
    ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H", 7.5),
    # Physical, all-none impact -> 0.0 (none); Impact <= 0 short-circuits.
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
    # Adjacent network, integrity-only low -> 4.3 (medium); exercises roundup.
    ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 4.3),
]


def test_known_vectors_base_scores() -> None:
    """Each documented vector recomputes to its published Base score."""
    for vector, expected in _KNOWN:
        got = _score(vector)
        assert got == expected, f"{vector}: expected {expected}, got {got}"


def test_known_vectors_bands() -> None:
    """Bands derived from the known scores match the v3.1 qualitative scale."""
    assert severity_band(_score(_KNOWN[0][0])) == "critical"  # 9.8
    assert severity_band(_score(_KNOWN[1][0])) == "medium"  # 6.5
    assert severity_band(_score(_KNOWN[2][0])) == "medium"  # 5.3
    assert severity_band(_score(_KNOWN[3][0])) == "critical"  # 10.0
    assert severity_band(_score(_KNOWN[4][0])) == "high"  # 7.5
    assert severity_band(_score(_KNOWN[6][0])) == "none"  # 0.0


# --- parse_vector -----------------------------------------------------------


def test_parse_vector_full() -> None:
    """A canonical vector parses into all eight Base metrics."""
    m = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert m == {
        "AV": "N",
        "AC": "L",
        "PR": "N",
        "UI": "N",
        "S": "U",
        "C": "H",
        "I": "H",
        "A": "H",
    }


def test_parse_vector_without_prefix() -> None:
    """The CVSS:3.1 prefix is optional."""
    m = parse_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert m["AV"] == "N" and m["A"] == "H"


def test_parse_vector_ignores_temporal_environmental() -> None:
    """Non-Base metrics (e.g. Exploit Code Maturity) are ignored."""
    m = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O")
    assert set(m) == {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}


def test_parse_vector_empty_raises() -> None:
    """An empty string raises ValueError."""
    _assert_raises_value_error(lambda: parse_vector("   "), contains="non-empty")


def test_parse_vector_missing_metric_raises() -> None:
    """A missing Base metric raises ValueError naming it."""
    _assert_raises_value_error(
        lambda: parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"),
        contains="A",
    )


def test_parse_vector_bad_value_raises() -> None:
    """An invalid metric value raises ValueError."""
    _assert_raises_value_error(
        lambda: parse_vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        contains="AV",
    )


def test_parse_vector_malformed_token_raises() -> None:
    """A token without a colon raises ValueError."""
    _assert_raises_value_error(
        lambda: parse_vector("CVSS:3.1/AVN/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        contains="malformed",
    )


def test_parse_vector_duplicate_metric_raises() -> None:
    """A duplicated Base metric raises ValueError."""
    _assert_raises_value_error(
        lambda: parse_vector("CVSS:3.1/AV:N/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        contains="duplicate",
    )


def test_parse_vector_bad_version_raises() -> None:
    """An unsupported version prefix raises ValueError."""
    _assert_raises_value_error(
        lambda: parse_vector("CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
        contains="version",
    )


# --- severity_band ----------------------------------------------------------


def test_severity_band_boundaries() -> None:
    """Band boundaries follow the v3.1 qualitative scale exactly."""
    assert severity_band(0.0) == "none"
    assert severity_band(0.1) == "low"
    assert severity_band(3.9) == "low"
    assert severity_band(4.0) == "medium"
    assert severity_band(6.9) == "medium"
    assert severity_band(7.0) == "high"
    assert severity_band(8.9) == "high"
    assert severity_band(9.0) == "critical"
    assert severity_band(10.0) == "critical"


def test_severity_band_out_of_range_raises() -> None:
    """A score outside [0, 10] raises ValueError."""
    _assert_raises_value_error(lambda: severity_band(10.1))
    _assert_raises_value_error(lambda: severity_band(-0.1))


# --- check_claimed ----------------------------------------------------------


def test_check_claimed_match() -> None:
    """A claimed score equal to the computed score is not a mismatch."""
    res = check_claimed("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8)
    assert res["computed"] == 9.8
    assert res["computed_band"] == "critical"
    assert res["mismatch"] is False
    assert res["delta"] == 0.0


def test_check_claimed_within_tolerance() -> None:
    """A claim off by < 0.05 is tolerated (display rounding)."""
    res = check_claimed("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.77)
    assert res["mismatch"] is False


def test_check_claimed_mismatch_arithmetic_slip() -> None:
    """A claimed 4.6 that actually recomputes to 6.5 is flagged as a mismatch.

    PR:L conf-only-high (scope U) is exactly 6.5; a reporter claiming 4.6
    (an easy arithmetic slip) must be caught.
    """
    res = check_claimed("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 4.6)
    assert res["computed"] == 6.5
    assert res["mismatch"] is True
    assert res["delta"] > 0.05
    assert res["computed_band"] == "medium"


def test_check_claimed_invalid_vector_raises() -> None:
    """An unparseable vector raises ValueError."""
    _assert_raises_value_error(lambda: check_claimed("not-a-vector", 5.0))


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
