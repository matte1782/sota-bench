"""Tests for sota_bench.triad: triad_gate and cia_concession_lint.

Dual-runnable: works under pytest, and also as a plain script
(``python sota_bench/tests/test_triad.py``) which runs every test function
and prints a PASS/FAIL summary.
"""

from __future__ import annotations

import os
import sys

# Make the package importable when run as a plain script from anywhere.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from sota_bench.triad import (  # noqa: E402
    TRIAD_AXES,
    cia_concession_lint,
    triad_gate,
)

# --- triad_gate: all-three-true (pass) --------------------------------------


def test_triad_gate_all_true_passes() -> None:
    """All three axes true -> passes, no reasons, not informative."""
    result = triad_gate(True, True, True)
    assert result["passes"] is True
    assert result["reasons"] == []
    assert "informative" not in result


# --- triad_gate: each-one-false (informative) -------------------------------


def test_triad_gate_boundary_false_informative() -> None:
    """First axis false -> informative, names the boundary axis."""
    result = triad_gate(False, True, True)
    assert result["passes"] is False
    assert result["informative"] is True
    assert result["reasons"] == ["axis not satisfied: crosses_lower_trust_boundary"]


def test_triad_gate_leak_false_informative() -> None:
    """Second axis false -> informative, names the leak axis."""
    result = triad_gate(True, False, True)
    assert result["passes"] is False
    assert result["informative"] is True
    assert result["reasons"] == ["axis not satisfied: leaks_sensitive_artifact"]


def test_triad_gate_consequence_false_informative() -> None:
    """Third axis false -> informative, names the consequence axis."""
    result = triad_gate(True, True, False)
    assert result["passes"] is False
    assert result["informative"] is True
    assert result["reasons"] == ["axis not satisfied: has_practical_consequence"]


def test_triad_gate_all_false_lists_every_axis() -> None:
    """All axes false -> informative with one reason per axis, in order."""
    result = triad_gate(False, False, False)
    assert result["passes"] is False
    assert result["informative"] is True
    reasons = result["reasons"]
    assert isinstance(reasons, list)
    assert len(reasons) == 3
    for axis, reason in zip(TRIAD_AXES, reasons):
        assert axis in reason


# --- cia_concession_lint: contradictory draft (fail) ------------------------


def test_cia_lint_disclosure_with_cn_vector_fails() -> None:
    """ "information disclosure" + C:N in the vector is a contradiction."""
    text = "This bug allows information disclosure of internal tokens."
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    result = cia_concession_lint(text, vector)
    assert result["passes"] is False
    reasons = result["reasons"]
    assert isinstance(reasons, list)
    assert len(reasons) == 1
    assert "Confidentiality" in reasons[0]


def test_cia_lint_disclosure_with_prose_concession_fails() -> None:
    """Explicit "Confidentiality: None" prose contradicts a disclosure claim."""
    text = "Enables data disclosure.\nConfidentiality: None"
    result = cia_concession_lint(text)
    assert result["passes"] is False
    assert any("Confidentiality" in r for r in result["reasons"])  # type: ignore[union-attr]


def test_cia_lint_rce_with_in_vector_fails() -> None:
    """An RCE claim under I:N is an Integrity contradiction."""
    text = "Leads to RCE on the worker node."
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    result = cia_concession_lint(text, vector)
    assert result["passes"] is False
    assert any("Integrity" in r for r in result["reasons"])  # type: ignore[union-attr]


# --- cia_concession_lint: consistent draft (pass) ---------------------------


def test_cia_lint_consistent_disclosure_passes() -> None:
    """A disclosure claim with C:H (axis honored) is consistent."""
    text = "This bug allows information disclosure of internal tokens."
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    result = cia_concession_lint(text, vector)
    assert result["passes"] is True
    assert result["reasons"] == []


def test_cia_lint_no_impact_claim_passes() -> None:
    """No impact keyword -> nothing to contradict, passes even with all-None."""
    text = "Minor cosmetic issue in the log formatting; no security impact."
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    result = cia_concession_lint(text, vector)
    assert result["passes"] is True
    assert result["reasons"] == []


def test_cia_lint_mismatched_axis_passes() -> None:
    """Disclosure (C) claim with only I:N conceded is not a contradiction."""
    text = "Allows information disclosure of secrets."
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    result = cia_concession_lint(text, vector)
    assert result["passes"] is True
    assert result["reasons"] == []


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
