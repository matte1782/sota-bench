"""Tests for the statistical-honesty layer (sota_bench.stats) and its wiring.

Significance and interval values are asserted against hand-computed textbook
numbers (the external source of truth), so a regression in the math is caught:

* McNemar two-sided exact-binomial p-values: b=0,c=10 -> 2*2^-10 = 0.001953125;
  b=1,c=8 -> 2*(C(9,0)+C(9,1))/2^9 = 20/512 = 0.0390625; symmetric b=c -> 1.0.
* Wilson 95% intervals: 0/10 -> (0.0, 0.2775), 10/10 -> (0.7225, 1.0),
  5/10 -> (0.2366, 0.7634).
* The power gate flips to UNDERPOWERED below 10 discordant pairs.

Dual-runnable: works under pytest and as a plain script
(``python tests/test_stats.py``).
"""

from __future__ import annotations

import math
import os
import sys
import tempfile
from collections.abc import Sequence

# Make the package importable when run as a plain script from anywhere.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from sota_bench.adapters import StubAdapter  # noqa: E402
from sota_bench.loop import load_baseline, pin_baseline, run_delta  # noqa: E402
from sota_bench.schema import BenchEntry, Prediction  # noqa: E402
from sota_bench.stats import (  # noqa: E402
    MIN_DISCORDANT_PAIRS,
    assess_power,
    confusion_cis,
    default_correct,
    mcnemar_exact,
    paired_correctness,
    paired_significance,
    significance_to_dict,
    wilson_ci,
)

# --- fixtures ---------------------------------------------------------------


def _entry(finding_id: str, ground_truth: str) -> BenchEntry:
    """Build a minimal valid BenchEntry with a given ground truth."""
    return BenchEntry(
        finding_id=finding_id,
        vertical="authz",
        repo="example/agent-app",
        commit_sha="deadbeefcafe",
        file="src/tools/admin.py",
        line=42,
        ground_truth=ground_truth,
        variant="baseline",
        owasp_labels=["API1:2023"],
        cwe=["CWE-862"],
        fp_killer="does the tool path enforce require_role()?",
        expected_cvss_band="high",
        expected_cvss_vector=None,
        realized_outcome="GHSA assigned",
        public_url=None,
        notes="stats test fixture",
    )


def _pred(finding_id: str, label: str) -> Prediction:
    """Build a Prediction with a given binary label."""
    return Prediction(
        finding_id=finding_id,
        predicted_label=label,
        predicted_cvss_score=None,
        predicted_cvss_band=None,
    )


# --- mcnemar_exact: textbook values -----------------------------------------


def test_mcnemar_no_discordant_is_one() -> None:
    """With no discordant pairs the test is uninformative (p = 1.0)."""
    res = mcnemar_exact(0, 0)
    assert res.p_value == 1.0
    assert res.n_discordant == 0
    assert res.favored == "tie"


def test_mcnemar_all_one_way_exact() -> None:
    """b=0, c=10 gives the exact two-sided p = 2 * 2^-10 = 0.001953125."""
    res = mcnemar_exact(0, 10)
    assert res.p_value == 0.001953125
    assert res.favored == "method"


def test_mcnemar_asymmetric_exact_and_symmetric_favor() -> None:
    """b=1, c=8 -> p = 20/512 = 0.0390625; direction follows the larger count."""
    res = mcnemar_exact(1, 8)
    assert res.p_value == 0.0390625
    assert res.favored == "method"
    mirror = mcnemar_exact(8, 1)
    assert mirror.p_value == 0.0390625
    assert mirror.favored == "naive"


def test_mcnemar_symmetric_is_one() -> None:
    """Equal discordant counts cap the two-sided p at 1.0 and favor neither."""
    res = mcnemar_exact(3, 3)
    assert res.p_value == 1.0
    assert res.favored == "tie"


def test_mcnemar_negative_raises() -> None:
    """Negative discordant counts are a programming error."""
    try:
        mcnemar_exact(-1, 2)
    except ValueError:
        return
    raise AssertionError("expected ValueError on negative discordant count")


# --- paired_correctness: scorer-identical scoping ---------------------------


def test_default_correct_matches_binarization() -> None:
    """A prediction is correct iff its label agrees with the vuln/secure truth."""
    assert default_correct(_entry("a", "vuln"), _pred("a", "vuln")) is True
    assert default_correct(_entry("a", "vuln"), _pred("a", "secure")) is False
    assert default_correct(_entry("b", "secure"), _pred("b", "secure")) is True
    assert default_correct(_entry("b", "secure"), _pred("b", "vuln")) is False


def test_paired_correctness_cells_and_exclusions() -> None:
    """The 2x2 cells are filled correctly and out-of-scope rows are excluded."""
    dataset = [
        _entry("both", "vuln"),  # naive vuln (ok), method vuln (ok) -> a
        _entry("naive_only", "vuln"),  # naive vuln (ok), method secure (wrong) -> b
        _entry("method_only", "vuln"),  # naive secure (wrong), method vuln (ok) -> c
        _entry("neither", "vuln"),  # naive secure (wrong), method secure (wrong) -> d
        _entry("oos_row", "oos"),  # excluded by ground truth
        _entry("no_method", "vuln"),  # has naive, missing method -> excluded
    ]
    naive = [
        _pred("both", "vuln"),
        _pred("naive_only", "vuln"),
        _pred("method_only", "secure"),
        _pred("neither", "secure"),
        _pred("no_method", "vuln"),
    ]
    method = [
        _pred("both", "vuln"),
        _pred("naive_only", "secure"),
        _pred("method_only", "vuln"),
        _pred("neither", "secure"),
    ]
    table = paired_correctness(dataset, naive, method)
    assert table.both_correct == 1
    assert table.naive_only_correct == 1
    assert table.method_only_correct == 1
    assert table.both_wrong == 1
    assert table.n_scored == 4
    assert table.n_discordant == 2
    assert table.n_excluded_ground_truth == 1
    assert table.n_missing_method == 1
    assert table.n_missing_naive == 0


def test_paired_correctness_duplicate_id_raises() -> None:
    """Duplicate finding_ids in predictions are rejected (scorer parity)."""
    dataset = [_entry("x", "vuln")]
    dup = [_pred("x", "vuln"), _pred("x", "secure")]
    try:
        paired_correctness(dataset, dup, [_pred("x", "vuln")])
    except ValueError:
        return
    raise AssertionError("expected ValueError on duplicate prediction finding_id")


# --- assess_power -----------------------------------------------------------


def _table(b: int, c: int, *, a: int = 0, d: int = 0):
    """Build predictions that realize a (b, c) discordance, then score them.

    ``b`` vuln rows where naive is right and method wrong; ``c`` vuln rows where
    naive is wrong and method right; ``a`` both-right and ``d`` both-wrong rows.
    """
    dataset: list[BenchEntry] = []
    naive: list[Prediction] = []
    method: list[Prediction] = []
    i = 0
    for _ in range(b):
        fid = f"b{i}"
        dataset.append(_entry(fid, "vuln"))
        naive.append(_pred(fid, "vuln"))
        method.append(_pred(fid, "secure"))
        i += 1
    for _ in range(c):
        fid = f"c{i}"
        dataset.append(_entry(fid, "vuln"))
        naive.append(_pred(fid, "secure"))
        method.append(_pred(fid, "vuln"))
        i += 1
    for _ in range(a):
        fid = f"a{i}"
        dataset.append(_entry(fid, "vuln"))
        naive.append(_pred(fid, "vuln"))
        method.append(_pred(fid, "vuln"))
        i += 1
    for _ in range(d):
        fid = f"d{i}"
        dataset.append(_entry(fid, "vuln"))
        naive.append(_pred(fid, "secure"))
        method.append(_pred(fid, "secure"))
        i += 1
    return dataset, naive, method


def test_power_underpowered_below_floor() -> None:
    """Below MIN_DISCORDANT_PAIRS the comparison is declared underpowered."""
    dataset, naive, method = _table(2, 3)
    table = paired_correctness(dataset, naive, method)
    verdict = assess_power(table)
    assert verdict.is_powered is False
    assert verdict.n_discordant == 5
    assert verdict.min_discordant == MIN_DISCORDANT_PAIRS


def test_power_met_at_floor() -> None:
    """Exactly MIN_DISCORDANT_PAIRS discordant pairs clears the gate."""
    dataset, naive, method = _table(0, MIN_DISCORDANT_PAIRS)
    table = paired_correctness(dataset, naive, method)
    verdict = assess_power(table)
    assert verdict.is_powered is True
    assert verdict.n_discordant == MIN_DISCORDANT_PAIRS


# --- paired_significance: combined verdict ----------------------------------


def test_significance_underpowered_blocks_claim() -> None:
    """An underpowered comparison yields significant=None and an UNDERPOWERED tag."""
    dataset, naive, method = _table(1, 3)
    verdict = paired_significance(dataset, naive, method)
    assert verdict.powered is False
    assert verdict.significant is None
    assert "UNDERPOWERED" in verdict.summary


def test_significance_powered_and_significant() -> None:
    """12 method-favoring discordant pairs is powered and significant."""
    dataset, naive, method = _table(0, 12)
    verdict = paired_significance(dataset, naive, method)
    assert verdict.powered is True
    assert verdict.significant is True
    assert verdict.favored == "method"
    # p = 2 * 2^-12 = 0.00048828125
    assert verdict.p_value == 0.00048828125


def test_significance_powered_but_not_significant() -> None:
    """Symmetric discordance (6 vs 6) is powered but not significant (p capped 1.0)."""
    dataset, naive, method = _table(6, 6)
    verdict = paired_significance(dataset, naive, method)
    assert verdict.powered is True
    assert verdict.significant is False
    assert verdict.p_value == 1.0
    assert verdict.favored == "tie"


def test_significance_to_dict_encodes_tristate() -> None:
    """The flattened map encodes the tri-state fields numerically, all floats."""
    under = significance_to_dict(paired_significance(*_table(1, 2)))
    assert under["powered"] == 0.0
    assert under["significant"] == -1.0  # undetermined
    assert set(under) == {
        "powered",
        "n_scored",
        "n_discordant",
        "mcnemar_p",
        "significant",
        "favored_method",
        "alpha",
    }
    assert all(isinstance(v, float) for v in under.values())

    sig = significance_to_dict(paired_significance(*_table(0, 12)))
    assert sig["powered"] == 1.0
    assert sig["significant"] == 1.0
    assert sig["favored_method"] == 1.0


# --- wilson_ci: textbook values ---------------------------------------------


def _approx(actual: tuple[float, float], lo: float, hi: float, tol: float = 1e-4) -> bool:
    return math.isclose(actual[0], lo, abs_tol=tol) and math.isclose(actual[1], hi, abs_tol=tol)


def test_wilson_known_intervals() -> None:
    """Wilson 95% intervals match the closed-form values."""
    assert _approx(wilson_ci(0, 10), 0.0, 0.2775)
    assert _approx(wilson_ci(10, 10), 0.7225, 1.0)
    assert _approx(wilson_ci(5, 10), 0.2366, 0.7634)


def test_wilson_zero_n_is_uninformative() -> None:
    """With no trials the interval is the whole unit interval."""
    assert wilson_ci(0, 0) == (0.0, 1.0)


def test_wilson_guards() -> None:
    """k > n and negative inputs are rejected."""
    for bad in (lambda: wilson_ci(3, 2), lambda: wilson_ci(-1, 5)):
        try:
            bad()
        except ValueError:
            continue
        raise AssertionError("expected ValueError on invalid Wilson inputs")


def test_confusion_cis_uses_right_denominators() -> None:
    """Each rate CI is the Wilson interval over its own numerator/denominator."""
    cis = confusion_cis(tp=4, fp=1, tn=9, fn=2)
    assert set(cis) == {"recall", "precision", "specificity", "fp_rate"}
    assert cis["recall"] == wilson_ci(4, 6)  # tp / (tp + fn)
    assert cis["precision"] == wilson_ci(4, 5)  # tp / (tp + fp)
    assert cis["specificity"] == wilson_ci(9, 10)  # tn / (tn + fp)
    assert cis["fp_rate"] == wilson_ci(1, 10)  # fp / (fp + tn)


# --- integration: run_delta attaches significance + round-trip --------------


def _predict_fn(entry: BenchEntry, raw: str) -> Prediction:
    return _pred(entry.finding_id, raw.strip().lower())


def _scorer_fn(
    dataset: Sequence[BenchEntry], predictions: Sequence[Prediction]
) -> dict[str, float]:
    by_id = {p.finding_id: p for p in predictions}
    tp = fn = 0
    for e in dataset:
        if e.ground_truth != "vuln":
            continue
        if by_id[e.finding_id].predicted_label == "vuln":
            tp += 1
        else:
            fn += 1
    return {"recall": tp / (tp + fn) if (tp + fn) else 0.0}


def test_run_delta_attaches_significance_and_roundtrips() -> None:
    """run_delta records the significance block, which survives pin/load."""
    dataset = [_entry("v1", "vuln"), _entry("s1", "secure")]
    naive = StubAdapter({}, default="secure")
    method = StubAdapter(
        {
            "does the tool path enforce require_role()?": "vuln",
        },
        default="secure",
    )
    result = run_delta(dataset, naive, method, _predict_fn, _scorer_fn, scorer_version="v1")
    assert result.significance is not None
    # Tiny corpus -> underpowered.
    assert result.significance["powered"] == 0.0
    assert result.significance["significant"] == -1.0

    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "baseline.json")
    try:
        pin_baseline(result, path)
        loaded = load_baseline(path)
    finally:
        if os.path.exists(path):
            os.remove(path)
        os.rmdir(tmpdir)
    assert loaded.significance == result.significance


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
