"""Tests for sota_bench.loop: the SOTA-validation delta loop.

Dual-runnable: works under pytest, and also as a plain script
(``python sota_bench/tests/test_loop.py``) which runs every test function and
prints a PASS/FAIL summary.

The central fixture builds a *known* naive-misses / method-hits split: a small
dataset of three entries where the naive single-call adapter clears two true
vulns (false negatives) while the method scaffold flags them correctly. With a
deterministic recall/precision/accuracy scorer, the signed delta is fully
determined, so we assert the exact numbers the loop must report.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections.abc import Sequence

# Make the package importable when run as a plain script from anywhere.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from sota_bench.adapters import ModelAdapter, StubAdapter  # noqa: E402
from sota_bench.loop import (  # noqa: E402
    DeltaResult,
    delta_vs_baseline,
    load_baseline,
    pin_baseline,
    run_delta,
    run_pass,
    signed_delta,
)
from sota_bench.schema import BenchEntry, Prediction  # noqa: E402


# --- fixtures ---------------------------------------------------------------


def _entry(finding_id: str, fp_killer: str, ground_truth: str) -> BenchEntry:
    """Build a minimal valid BenchEntry for loop tests."""
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
        fp_killer=fp_killer,
        expected_cvss_band="high",
        expected_cvss_vector=None,
        realized_outcome="GHSA assigned",
        public_url=None,
        notes="loop test fixture",
    )


def _dataset() -> list[BenchEntry]:
    """Three entries: two true vulns and one truly-secure patched twin."""
    return [
        _entry("authz-0001", "tool path skips require_role()", "vuln"),
        _entry("authz-0002", "tool path skips tenant scoping", "vuln"),
        _entry("authz-0003", "patched: require_role() now guards dispatch", "secure"),
    ]


def _predict_fn(entry: BenchEntry, raw: str) -> Prediction:
    """Parse a stub's raw text ('vuln'|'secure') into a Prediction."""
    label = raw.strip().lower()
    assert label in {"vuln", "secure"}, f"unexpected stub output: {raw!r}"
    return Prediction(
        finding_id=entry.finding_id,
        predicted_label=label,
        predicted_cvss_score=None,
        predicted_cvss_band=None,
    )


def _scorer_fn(
    dataset: Sequence[BenchEntry], predictions: Sequence[Prediction]
) -> dict[str, float]:
    """Deterministic accuracy/recall/precision over the vuln class.

    Treats ``ground_truth == "vuln"`` as positive and any non-vuln label as
    negative; predictions are already binary ('vuln'|'secure'). Pure arithmetic,
    no judge.
    """
    by_id = {p.finding_id: p for p in predictions}
    tp = fp = tn = fn = 0
    for e in dataset:
        pred = by_id[e.finding_id].predicted_label
        actual_pos = e.ground_truth == "vuln"
        pred_pos = pred == "vuln"
        if actual_pos and pred_pos:
            tp += 1
        elif actual_pos and not pred_pos:
            fn += 1
        elif not actual_pos and pred_pos:
            fp += 1
        else:
            tn += 1
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    return {"accuracy": accuracy, "recall": recall, "precision": precision}


# --- StubAdapter ------------------------------------------------------------


def test_stub_adapter_mapping() -> None:
    """A mapping StubAdapter returns canned outputs by exact prompt."""
    stub = StubAdapter({"q1": "vuln", "q2": "secure"})
    assert stub.run("q1") == "vuln"
    assert stub.run("q2") == "secure"


def test_stub_adapter_missing_key_raises() -> None:
    """A mapping StubAdapter with no default raises KeyError on a miss."""
    stub = StubAdapter({"q1": "vuln"})
    try:
        stub.run("unknown")
    except KeyError:
        return
    raise AssertionError("expected KeyError for unmapped prompt")


def test_stub_adapter_default() -> None:
    """A default is returned for unmapped prompts when provided."""
    stub = StubAdapter({"q1": "vuln"}, default="secure")
    assert stub.run("anything-else") == "secure"


def test_stub_adapter_callable() -> None:
    """A callable StubAdapter is invoked with the prompt."""
    stub = StubAdapter(lambda p: "vuln" if "skips" in p else "secure")
    assert stub.run("tool path skips X") == "vuln"
    assert stub.run("all good") == "secure"


def test_stub_adapter_bad_type() -> None:
    """A non-mapping, non-callable responses argument raises TypeError."""
    try:
        StubAdapter(123)  # type: ignore[arg-type]
    except TypeError:
        return
    raise AssertionError("expected TypeError for bad responses type")


def test_stub_adapter_is_model_adapter() -> None:
    """StubAdapter satisfies the ModelAdapter interface."""
    assert isinstance(StubAdapter({}), ModelAdapter)


# --- run_pass ---------------------------------------------------------------


def test_run_pass_keys_on_fp_killer() -> None:
    """run_pass builds prompts from fp_killer by default and parses outputs."""
    dataset = _dataset()
    mapping = {
        "tool path skips require_role()": "vuln",
        "tool path skips tenant scoping": "vuln",
        "patched: require_role() now guards dispatch": "secure",
    }
    preds = run_pass(dataset, StubAdapter(mapping), _predict_fn)
    assert [p.predicted_label for p in preds] == ["vuln", "vuln", "secure"]
    assert [p.finding_id for p in preds] == ["authz-0001", "authz-0002", "authz-0003"]


# --- signed_delta -----------------------------------------------------------


def test_signed_delta_basic() -> None:
    """signed_delta subtracts naive from method key-for-key."""
    d = signed_delta({"a": 1.0, "b": 0.5}, {"a": 0.25, "b": 0.5})
    assert d == {"a": 0.75, "b": 0.0}


def test_signed_delta_key_mismatch_raises() -> None:
    """Mismatched metric key sets raise ValueError."""
    try:
        signed_delta({"a": 1.0}, {"b": 1.0})
    except ValueError:
        return
    raise AssertionError("expected ValueError on key mismatch")


# --- run_delta: the known split ---------------------------------------------


def _naive_adapter() -> StubAdapter:
    """Naive single call: clears BOTH true vulns (two false negatives)."""
    return StubAdapter(
        {
            "tool path skips require_role()": "secure",
            "tool path skips tenant scoping": "secure",
            "patched: require_role() now guards dispatch": "secure",
        }
    )


def _method_adapter() -> StubAdapter:
    """Method scaffold: flags both true vulns, clears the patched twin (perfect)."""
    return StubAdapter(
        {
            "tool path skips require_role()": "vuln",
            "tool path skips tenant scoping": "vuln",
            "patched: require_role() now guards dispatch": "secure",
        }
    )


def test_run_delta_known_split() -> None:
    """The naive-misses / method-hits split yields the exact signed deltas.

    Naive: tp=0, fn=2, tn=1, fp=0 -> accuracy=1/3, recall=0, precision=0.
    Method: tp=2, fn=0, tn=1, fp=0 -> accuracy=1.0, recall=1.0, precision=1.0.
    Delta (method - naive): accuracy=2/3, recall=1.0, precision=1.0.
    """
    result = run_delta(
        _dataset(),
        _naive_adapter(),
        _method_adapter(),
        _predict_fn,
        _scorer_fn,
        model_label="frontier-2026.06",
        dataset_fingerprint="corpus-v1",
    )
    assert isinstance(result, DeltaResult)

    assert result.naive_metrics["recall"] == 0.0
    assert result.naive_metrics["precision"] == 0.0
    assert abs(result.naive_metrics["accuracy"] - (1 / 3)) < 1e-12

    assert result.method_metrics == {"accuracy": 1.0, "recall": 1.0, "precision": 1.0}

    assert result.delta["recall"] == 1.0
    assert result.delta["precision"] == 1.0
    assert abs(result.delta["accuracy"] - (2 / 3)) < 1e-12

    assert result.model_label == "frontier-2026.06"
    assert result.dataset_fingerprint == "corpus-v1"


def test_run_delta_no_improvement_is_zero() -> None:
    """When method == naive, every signed delta is exactly zero."""
    result = run_delta(
        _dataset(),
        _method_adapter(),
        _method_adapter(),
        _predict_fn,
        _scorer_fn,
    )
    assert result.delta == {"accuracy": 0.0, "recall": 0.0, "precision": 0.0}


# --- pin / load / delta_vs_baseline round-trip ------------------------------


def test_pin_load_roundtrip() -> None:
    """pin_baseline then load_baseline reconstructs an equal DeltaResult."""
    result = run_delta(
        _dataset(),
        _naive_adapter(),
        _method_adapter(),
        _predict_fn,
        _scorer_fn,
        model_label="frontier-2026.06",
        dataset_fingerprint="corpus-v1",
    )
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        pin_baseline(result, path)
        loaded = load_baseline(path)
    finally:
        os.remove(path)

    assert loaded.model_label == result.model_label
    assert loaded.dataset_fingerprint == result.dataset_fingerprint
    assert loaded.naive_metrics == result.naive_metrics
    assert loaded.method_metrics == result.method_metrics
    assert loaded.delta == result.delta
    assert loaded.format_version == result.format_version


def test_delta_vs_baseline_zero_against_self() -> None:
    """delta_vs_baseline of a result against itself is all zeros."""
    result = run_delta(_dataset(), _naive_adapter(), _method_adapter(), _predict_fn, _scorer_fn)
    movement = delta_vs_baseline(result, result)
    assert movement == {"accuracy": 0.0, "recall": 0.0, "precision": 0.0}


def test_delta_vs_baseline_release_over_release() -> None:
    """A later release whose method edge shrinks shows a negative movement.

    Baseline release: method beats naive by recall=+1.0.
    New release: naive itself now catches one vuln, so the method's *edge*
    shrinks; delta_vs_baseline reports the signed change in that edge.
    """
    baseline = run_delta(
        _dataset(),
        _naive_adapter(),
        _method_adapter(),
        _predict_fn,
        _scorer_fn,
        model_label="frontier-2026.06",
    )

    # New release: the naive call now catches authz-0001 (edge shrinks).
    improved_naive = StubAdapter(
        {
            "tool path skips require_role()": "vuln",
            "tool path skips tenant scoping": "secure",
            "patched: require_role() now guards dispatch": "secure",
        }
    )
    new_result = run_delta(
        _dataset(),
        improved_naive,
        _method_adapter(),
        _predict_fn,
        _scorer_fn,
        model_label="frontier-2026.07",
    )

    movement = delta_vs_baseline(new_result, baseline)
    # Baseline recall delta was +1.0; new recall delta is +0.5 -> movement -0.5.
    assert abs(new_result.delta["recall"] - 0.5) < 1e-12
    assert abs(movement["recall"] - (-0.5)) < 1e-12


def test_load_baseline_rejects_future_version() -> None:
    """A baseline with a future format_version is rejected."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    payload = {
        "model_label": "x",
        "dataset_fingerprint": "y",
        "naive_metrics": {"recall": 0.0},
        "method_metrics": {"recall": 1.0},
        "delta": {"recall": 1.0},
        "format_version": 999,
    }
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        try:
            load_baseline(path)
        except ValueError:
            return
        finally:
            pass
    finally:
        os.remove(path)
    raise AssertionError("expected ValueError for future format_version")


def test_load_baseline_rejects_missing_field() -> None:
    """A baseline missing a required field is rejected."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    payload = {
        "model_label": "x",
        "dataset_fingerprint": "y",
        "naive_metrics": {"recall": 0.0},
        # method_metrics omitted
        "delta": {"recall": 1.0},
    }
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        try:
            load_baseline(path)
        except ValueError:
            return
        finally:
            pass
    finally:
        os.remove(path)
    raise AssertionError("expected ValueError for missing field")


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
