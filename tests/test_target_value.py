"""Tests for the deterministic target-value (blast-radius) gate.

Covers the pure :func:`decide_tier` ladder exhaustively (tier boundaries, the
criticality fallback, the null != 0 fail-safe, both-unavailable -> reject+override,
downloads-never-promote, input validation, determinism) and the live fetch layer
with the module's HTTP call swapped for canned deps.dev shapes (verified against
the real v3 / v3alpha responses on 2026-06-06). No network, no randomness.

Dual-runnable: works under pytest and as a plain script.
"""

from __future__ import annotations

import contextlib
import http.client
import os
import sys
import urllib.error
from collections.abc import Iterator
from typing import Any

# Make the package importable when run as a plain script from anywhere.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

import sota_bench.target_value as tv  # noqa: E402
from sota_bench.target_value import (  # noqa: E402
    TargetValueReport,
    decide_tier,
    fetch_dependents,
    resolve_default_version,
    score_target,
)


@contextlib.contextmanager
def _swap(attr: str, value: Any) -> Iterator[None]:
    """Temporarily replace ``tv.<attr>`` (white-box stub), restoring after."""
    old = getattr(tv, attr)
    setattr(tv, attr, value)
    try:
        yield
    finally:
        setattr(tv, attr, old)


def _raises(exc: type[BaseException], fn: Any, *args: Any, **kwargs: Any) -> None:
    """Assert ``fn(*args, **kwargs)`` raises ``exc`` (script-safe, no pytest dep)."""
    try:
        fn(*args, **kwargs)
    except exc:
        return
    except Exception as other:  # noqa: BLE001
        raise AssertionError(
            f"expected {exc.__name__}, got {type(other).__name__}: {other}"
        ) from None
    raise AssertionError(f"expected {exc.__name__}, but nothing was raised")


# --- decide_tier: dependents ladder -----------------------------------------


def test_tier1_by_dependents_floor() -> None:
    r = decide_tier(direct_dependents=5000, criticality=None)
    assert r.tier == "tier1" and r.primary_axis == "dependents"
    assert r.manual_override_required is False


def test_tier1_by_dependents_large() -> None:
    # requests-class library (live: directDependentCount 83995).
    r = decide_tier(direct_dependents=83995, criticality=None)
    assert r.tier == "tier1" and r.primary_axis == "dependents"


def test_tier2_by_dependents_floor_and_just_below_t1() -> None:
    assert decide_tier(direct_dependents=500, criticality=None).tier == "tier2"
    assert decide_tier(direct_dependents=4999, criticality=None).tier == "tier2"


def test_tier3_by_dependents_floor_and_just_below_t2() -> None:
    assert decide_tier(direct_dependents=50, criticality=None).tier == "tier3"
    assert decide_tier(direct_dependents=499, criticality=None).tier == "tier3"


def test_fast_reject_low_dep_no_crit_requires_override() -> None:
    # Low dependents AND criticality never measured -> reject, but NOT silent:
    # the unattempted second signal (the one that matters for frameworks/apps,
    # R6) escalates to a logged operator decision.
    r = decide_tier(direct_dependents=49, criticality=None)
    assert r.tier == "reject" and r.primary_axis == "none"
    assert r.manual_override_required is True
    assert any("criticality unavailable" in reason for reason in r.reasons)


def test_fast_reject_low_dep_measured_low_crit_no_override() -> None:
    # Both signals measured and both small -> a CONFIDENT reject (no override).
    r = decide_tier(direct_dependents=49, criticality=0.30)
    assert r.tier == "reject" and r.primary_axis == "none"
    assert r.manual_override_required is False


def test_zero_dependents_is_not_missing() -> None:
    # d=0 is a real measured value (< floor) -> reject; distinct from d=None.
    r = decide_tier(direct_dependents=0, criticality=None)
    assert r.tier == "reject"
    assert r.direct_dependents == 0  # recorded as 0, not coerced to None


# --- decide_tier: criticality fallback --------------------------------------


def test_tier1_by_criticality_fallback() -> None:
    r = decide_tier(direct_dependents=None, criticality=0.80)
    assert r.tier == "tier1" and r.primary_axis == "criticality"


def test_tier2_tier3_by_criticality() -> None:
    assert decide_tier(direct_dependents=None, criticality=0.60).tier == "tier2"
    assert decide_tier(direct_dependents=None, criticality=0.40).tier == "tier3"


def test_reject_by_low_criticality() -> None:
    r = decide_tier(direct_dependents=None, criticality=0.39)
    assert r.tier == "reject" and r.manual_override_required is False


def test_null_dependents_uses_criticality_not_zero() -> None:
    # d=None must NOT be read as 0 in the fast-reject; criticality decides.
    r = decide_tier(direct_dependents=None, criticality=0.50)
    assert r.tier == "tier3" and r.primary_axis == "criticality"


# --- decide_tier: mixed signals + higher-tier-wins --------------------------


def test_high_criticality_promotes_above_dep_tier() -> None:
    # d alone would be tier3 (100>=50); c=0.85 lifts it to tier1.
    r = decide_tier(direct_dependents=100, criticality=0.85)
    assert r.tier == "tier1" and r.primary_axis == "criticality"


def test_low_dep_high_crit_skips_fast_reject() -> None:
    # d=10 (<50) but c>=0.40 -> NOT fast-rejected; c decides the tier.
    r = decide_tier(direct_dependents=10, criticality=0.85)
    assert r.tier == "tier1"


def test_dep_wins_axis_when_both_satisfy_same_tier() -> None:
    r = decide_tier(direct_dependents=6000, criticality=0.95)
    assert r.tier == "tier1" and r.primary_axis == "dependents"


# --- decide_tier: both unavailable + override -------------------------------


def test_both_unavailable_rejects_with_override() -> None:
    r = decide_tier(direct_dependents=None, criticality=None)
    assert r.tier == "reject" and r.primary_axis == "none"
    assert r.manual_override_required is True
    assert any("manual operator override" in reason for reason in r.reasons)


# --- decide_tier: downloads never promote -----------------------------------


def test_downloads_recorded_but_never_promote() -> None:
    r = decide_tier(direct_dependents=100, criticality=None, downloads=10**9)
    assert r.tier == "tier3"  # 100 -> tier3 regardless of huge downloads
    assert r.downloads == 10**9


# --- decide_tier: validation (fail closed) ----------------------------------


def test_validation_rejects_negative_and_bool_dependents() -> None:
    _raises(ValueError, decide_tier, direct_dependents=-1, criticality=None)
    _raises(ValueError, decide_tier, direct_dependents=True, criticality=None)


def test_validation_rejects_out_of_range_and_bool_criticality() -> None:
    _raises(ValueError, decide_tier, direct_dependents=None, criticality=1.5)
    _raises(ValueError, decide_tier, direct_dependents=None, criticality=-0.1)
    _raises(ValueError, decide_tier, direct_dependents=None, criticality=True)


def test_criticality_boundary_values_valid() -> None:
    assert decide_tier(direct_dependents=None, criticality=0.0).tier == "reject"
    assert decide_tier(direct_dependents=None, criticality=1.0).tier == "tier1"


# --- decide_tier: determinism + custom thresholds + provenance ---------------


def test_decide_tier_is_deterministic() -> None:
    a = decide_tier(direct_dependents=500, criticality=0.5, fetched_at="2026-06-06")
    b = decide_tier(direct_dependents=500, criticality=0.5, fetched_at="2026-06-06")
    assert a == b
    assert isinstance(a, TargetValueReport)


def test_custom_thresholds_are_honored() -> None:
    r = decide_tier(direct_dependents=10, criticality=None, t1_dep=10, reject_dep_floor=5)
    assert r.tier == "tier1"


def test_provenance_fields_pass_through() -> None:
    r = decide_tier(
        direct_dependents=600,
        criticality=None,
        system="pypi",
        resolved_version="2.34.2",
        total_dependents=167580,
        fetched_at="2026-06-06",
    )
    assert r.system == "pypi"
    assert r.resolved_version == "2.34.2"
    assert r.total_dependents == 167580
    assert r.fetched_at == "2026-06-06"


# --- fetch layer: resolve_default_version (HTTP swapped) ---------------------

_V3_REQUESTS = {
    "versions": [
        {"versionKey": {"version": "2.30.0"}, "isDefault": False},
        {"versionKey": {"version": "2.34.2"}, "isDefault": True},
    ]
}


def test_resolve_default_version_picks_isdefault() -> None:
    with _swap("_http_get_json", lambda url, *, timeout: _V3_REQUESTS):
        assert resolve_default_version("pypi", "requests") == "2.34.2"


def test_resolve_default_version_none_when_no_default() -> None:
    payload = {"versions": [{"versionKey": {"version": "1.0.0"}, "isDefault": False}]}
    with _swap("_http_get_json", lambda url, *, timeout: payload):
        assert resolve_default_version("pypi", "x") is None


def test_resolve_default_version_none_on_404() -> None:
    with _swap("_http_get_json", lambda url, *, timeout: None):
        assert resolve_default_version("pypi", "nope") is None


def test_resolve_default_version_rejects_unsupported_system() -> None:
    _raises(ValueError, resolve_default_version, "rubygems", "rails")


# --- fetch layer: fetch_dependents (HTTP swapped) ---------------------------

_V3ALPHA_REQUESTS = {
    "dependentCount": 167580,
    "directDependentCount": 83995,
    "indirectDependentCount": 87732,
}


def test_fetch_dependents_parses_real_shape() -> None:
    with _swap("_http_get_json", lambda url, *, timeout: _V3ALPHA_REQUESTS):
        direct, total = fetch_dependents("pypi", "requests", "2.34.2")
    assert direct == 83995 and total == 167580


def test_fetch_dependents_404_is_none_not_zero() -> None:
    with _swap("_http_get_json", lambda url, *, timeout: None):
        direct, total = fetch_dependents("go", "github.com/gorilla/mux", "v1.8.1")
    assert direct is None and total is None  # NOT (0, 0)


def test_fetch_dependents_rejects_unsupported_system() -> None:
    _raises(ValueError, fetch_dependents, "rubygems", "rails", "7.0.0")


# --- score_target: end-to-end (fetch helpers swapped) -----------------------


def test_score_target_tier1_from_dependents() -> None:
    with (
        _swap("resolve_default_version", lambda s, p, *, timeout=10.0: "2.34.2"),
        _swap("fetch_dependents", lambda s, p, v, *, timeout=10.0: (83995, 167580)),
    ):
        r = score_target(system="pypi", package="requests", today="2026-06-06")
    assert r.tier == "tier1" and r.primary_axis == "dependents"
    assert r.resolved_version == "2.34.2" and r.fetched_at == "2026-06-06"


def test_score_target_404_falls_back_to_criticality() -> None:
    with (
        _swap("resolve_default_version", lambda s, p, *, timeout=10.0: "v1.8.1"),
        _swap("fetch_dependents", lambda s, p, v, *, timeout=10.0: (None, None)),
    ):
        r = score_target(
            system="go", package="github.com/gorilla/mux", criticality=0.85, today="2026-06-06"
        )
    assert r.tier == "tier1" and r.primary_axis == "criticality"
    assert any("fell back to criticality" in reason for reason in r.reasons)


def test_score_target_fetch_error_fails_safe() -> None:
    def _boom(s: str, p: str, *, timeout: float = 10.0) -> str | None:
        raise urllib.error.URLError("network down")

    with _swap("resolve_default_version", _boom):
        r = score_target(system="pypi", package="requests", criticality=0.70, today="2026-06-06")
    assert r.tier == "tier2" and r.primary_axis == "criticality"  # 0.70 -> tier2
    assert any("fetch error" in reason for reason in r.reasons)


def test_score_target_both_unavailable_requires_override() -> None:
    with (
        _swap("resolve_default_version", lambda s, p, *, timeout=10.0: None),
        _swap("fetch_dependents", lambda s, p, v, *, timeout=10.0: (None, None)),
    ):
        r = score_target(system="pypi", package="ghost", today="2026-06-06")
    assert r.tier == "reject" and r.manual_override_required is True


# --- _http_get_json: 404 vs non-404 vs non-dict (urlopen-level, not stubbed away) ---


class _FakeResp:
    """Minimal context-manager response with a ``read()`` returning bytes."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def read(self) -> bytes:
        return self._body


@contextlib.contextmanager
def _swap_urlopen(fn: Any) -> Iterator[None]:
    """Swap the real ``urllib.request.urlopen`` that the module calls through."""
    import urllib.request as ur

    old = ur.urlopen
    ur.urlopen = fn
    try:
        yield
    finally:
        ur.urlopen = old


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://api.deps.dev/x", code, "err", {}, None)  # type: ignore[arg-type]


def test_http_get_json_404_returns_none() -> None:
    def _open(req: Any, timeout: float | None = None) -> _FakeResp:
        raise _http_error(404)

    with _swap_urlopen(_open):
        assert tv._http_get_json("https://api.deps.dev/x", timeout=5.0) is None


def test_http_get_json_non_404_reraises() -> None:
    def _open(req: Any, timeout: float | None = None) -> _FakeResp:
        raise _http_error(500)

    with _swap_urlopen(_open):
        _raises(urllib.error.HTTPError, tv._http_get_json, "https://api.deps.dev/x", timeout=5.0)


def test_http_get_json_non_dict_body_raises() -> None:
    # A JSON array (not an object) must fail closed, never be silently accepted.
    with _swap_urlopen(lambda req, timeout=None: _FakeResp(b'["a", "b"]')):
        _raises(ValueError, tv._http_get_json, "https://api.deps.dev/x", timeout=5.0)


def test_score_target_server_500_fails_safe_to_criticality() -> None:
    # A 500 from resolve's HTTP call must fall back, NOT be read as "absent".
    def _open(req: Any, timeout: float | None = None) -> _FakeResp:
        raise _http_error(500)

    with _swap_urlopen(_open):
        r = score_target(system="pypi", package="requests", criticality=0.70, today="2026-06-06")
    assert r.tier == "tier2" and r.primary_axis == "criticality"
    assert any("fetch error" in reason for reason in r.reasons)


def test_score_target_incomplete_read_fails_safe() -> None:
    # IncompleteRead is HTTPException-only (NOT an OSError); the handler must catch it.
    def _boom(s: str, p: str, *, timeout: float = 10.0) -> str | None:
        raise http.client.IncompleteRead(b"", 0)

    with _swap("resolve_default_version", _boom):
        r = score_target(system="pypi", package="requests", criticality=0.85, today="2026-06-06")
    assert r.tier == "tier1" and r.primary_axis == "criticality"
    assert any("fetch error" in reason for reason in r.reasons)


def test_score_target_unsupported_system_fails_safe() -> None:
    # rubygems is unsupported -> resolve raises ValueError -> caught -> fall back.
    r = score_target(system="rubygems", package="rails", criticality=0.85, today="2026-06-06")
    assert r.tier == "tier1" and r.primary_axis == "criticality"
    assert any("fetch error" in reason for reason in r.reasons)


# --- malformed-but-200 payloads degrade to None (unstable v3alpha, R1/R11) ---


def test_fetch_dependents_malformed_counts_are_none() -> None:
    bad = {"directDependentCount": "oops", "dependentCount": -5, "indirectDependentCount": 1}
    with _swap("_http_get_json", lambda url, *, timeout: bad):
        direct, total = fetch_dependents("pypi", "x", "1.0.0")
    assert direct is None  # str -> None
    assert total is None  # negative -> None


def test_fetch_dependents_bool_count_is_none() -> None:
    with _swap("_http_get_json", lambda url, *, timeout: {"directDependentCount": True}):
        direct, _ = fetch_dependents("pypi", "x", "1.0.0")
    assert direct is None  # bool is not a valid count


def test_resolve_default_version_malformed_payloads() -> None:
    cases: list[dict[str, Any]] = [
        {},  # no versions key
        {"versions": "oops"},  # versions not a list
        {"versions": [{"isDefault": True}]},  # default entry missing versionKey
        {"versions": [{"versionKey": {"version": 123}, "isDefault": True}]},  # non-str version
    ]
    for payload in cases:
        with _swap("_http_get_json", lambda url, *, timeout, _p=payload: _p):
            assert resolve_default_version("pypi", "x") is None


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
