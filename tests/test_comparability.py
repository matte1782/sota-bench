"""Tests for the L1 comparability wall in sota_bench.loop.

These cover the content-addressed comparability guarantees added on top of the
delta loop:

* :func:`fingerprint_dataset` is a deterministic, order-independent, content
  hash of the exact scored corpus.
* :func:`run_delta` stamps that computed ``dataset_hash`` (the caller cannot
  forge it) and carries the declared ``scorer_version``.
* :func:`delta_vs_baseline` REFUSES to difference two runs unless both their
  ``dataset_hash`` and ``scorer_version`` match (the binding gate).
* :func:`pin_baseline` is write-once by default (refuses to clobber a non-empty
  baseline without ``overwrite=True``).
* :func:`load_baseline` round-trips the new fields and tolerates a legacy v1
  baseline by filling the non-comparable sentinels.
* :func:`scorer_source_version` is a deterministic, change-sensitive tag.

Dual-runnable: works under pytest, and also as a plain script
(``python tests/test_comparability.py``) which runs every test and prints a
PASS/FAIL summary.
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

from sota_bench.adapters import StubAdapter  # noqa: E402
from sota_bench.loop import (  # noqa: E402
    DATASET_HASH_UNHASHED,
    SCORER_VERSION_UNSET,
    delta_vs_baseline,
    fingerprint_dataset,
    load_baseline,
    pin_baseline,
    run_delta,
    scorer_source_version,
)
from sota_bench.schema import BenchEntry, Prediction  # noqa: E402

# --- fixtures ---------------------------------------------------------------


def _entry(finding_id: str, fp_killer: str, ground_truth: str) -> BenchEntry:
    """Build a minimal valid BenchEntry for comparability tests."""
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
        notes="comparability test fixture",
    )


def _dataset() -> list[BenchEntry]:
    """Two entries: one true vuln and one patched-secure twin."""
    return [
        _entry("authz-0001", "tool path skips require_role()", "vuln"),
        _entry("authz-0002", "patched: require_role() now guards dispatch", "secure"),
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
    """Deterministic recall over the vuln class. Pure arithmetic, no judge."""
    by_id = {p.finding_id: p for p in predictions}
    tp = fn = 0
    for e in dataset:
        pred_pos = by_id[e.finding_id].predicted_label == "vuln"
        if e.ground_truth == "vuln":
            if pred_pos:
                tp += 1
            else:
                fn += 1
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return {"recall": recall}


def _naive() -> StubAdapter:
    """Naive single call: clears the true vuln (a false negative)."""
    return StubAdapter(
        {
            "tool path skips require_role()": "secure",
            "patched: require_role() now guards dispatch": "secure",
        }
    )


def _method() -> StubAdapter:
    """Method scaffold: flags the true vuln, clears the patched twin."""
    return StubAdapter(
        {
            "tool path skips require_role()": "vuln",
            "patched: require_role() now guards dispatch": "secure",
        }
    )


# --- fingerprint_dataset ----------------------------------------------------


def test_fingerprint_is_sha256_prefixed() -> None:
    """The fingerprint is a 'sha256:' + 64 hex-char digest."""
    fp = fingerprint_dataset(_dataset())
    assert fp.startswith("sha256:")
    digest = fp.split(":", 1)[1]
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_fingerprint_is_deterministic() -> None:
    """The same content yields the same fingerprint across rebuilds."""
    assert fingerprint_dataset(_dataset()) == fingerprint_dataset(_dataset())


def test_fingerprint_is_order_independent() -> None:
    """Reordering rows does not change the fingerprint (set-of-rows semantics)."""
    forward = _dataset()
    reversed_rows = list(reversed(_dataset()))
    assert fingerprint_dataset(forward) == fingerprint_dataset(reversed_rows)


def test_fingerprint_changes_on_any_field_edit() -> None:
    """Editing any field of any row changes the fingerprint."""
    base = _dataset()
    mutated = _dataset()
    # Flip the ground_truth of the first row.
    mutated[0] = _entry("authz-0001", "tool path skips require_role()", "secure")
    assert fingerprint_dataset(base) != fingerprint_dataset(mutated)


def test_fingerprint_changes_on_added_row() -> None:
    """Appending a row changes the fingerprint (a grown corpus is a new hash)."""
    base = _dataset()
    grown = _dataset() + [_entry("authz-0003", "another skipped check", "vuln")]
    assert fingerprint_dataset(base) != fingerprint_dataset(grown)


# --- run_delta stamps the comparability key ---------------------------------


def test_run_delta_stamps_computed_hash() -> None:
    """run_delta computes dataset_hash from the dataset, not from any caller arg."""
    dataset = _dataset()
    result = run_delta(
        dataset,
        _naive(),
        _method(),
        _predict_fn,
        _scorer_fn,
        dataset_fingerprint="a-cosmetic-label",
        scorer_version="scorer-vX",
    )
    assert result.dataset_hash == fingerprint_dataset(dataset)
    assert result.scorer_version == "scorer-vX"
    # The cosmetic label is preserved but is NOT the comparability key.
    assert result.dataset_fingerprint == "a-cosmetic-label"
    assert result.dataset_fingerprint != result.dataset_hash


def test_run_delta_scorer_version_defaults_to_unset() -> None:
    """A run that does not declare a scorer_version is marked non-publishable."""
    result = run_delta(_dataset(), _naive(), _method(), _predict_fn, _scorer_fn)
    assert result.scorer_version == SCORER_VERSION_UNSET


# --- delta_vs_baseline: the binding gate ------------------------------------


def test_gate_passes_when_corpus_and_scorer_match() -> None:
    """Matching dataset_hash + scorer_version difference cleanly."""
    baseline = run_delta(
        _dataset(), _naive(), _method(), _predict_fn, _scorer_fn, scorer_version="v1"
    )
    new = run_delta(_dataset(), _naive(), _method(), _predict_fn, _scorer_fn, scorer_version="v1")
    movement = delta_vs_baseline(new, baseline)
    assert movement == {"recall": 0.0}


def test_gate_raises_on_corpus_mismatch() -> None:
    """A different corpus (different dataset_hash) cannot be differenced."""
    baseline = run_delta(
        _dataset(), _naive(), _method(), _predict_fn, _scorer_fn, scorer_version="v1"
    )
    grown = _dataset() + [_entry("authz-0003", "another skipped check", "vuln")]
    grown_naive = StubAdapter(
        {
            "tool path skips require_role()": "secure",
            "patched: require_role() now guards dispatch": "secure",
            "another skipped check": "secure",
        }
    )
    grown_method = StubAdapter(
        {
            "tool path skips require_role()": "vuln",
            "patched: require_role() now guards dispatch": "secure",
            "another skipped check": "vuln",
        }
    )
    new = run_delta(grown, grown_naive, grown_method, _predict_fn, _scorer_fn, scorer_version="v1")
    try:
        delta_vs_baseline(new, baseline)
    except ValueError as exc:
        assert "corpus mismatch" in str(exc)
        return
    raise AssertionError("expected ValueError on dataset_hash mismatch")


def test_gate_raises_on_scorer_mismatch() -> None:
    """Same corpus but a different scorer_version cannot be differenced."""
    baseline = run_delta(
        _dataset(), _naive(), _method(), _predict_fn, _scorer_fn, scorer_version="v1"
    )
    new = run_delta(_dataset(), _naive(), _method(), _predict_fn, _scorer_fn, scorer_version="v2")
    try:
        delta_vs_baseline(new, baseline)
    except ValueError as exc:
        assert "scorer mismatch" in str(exc)
        return
    raise AssertionError("expected ValueError on scorer_version mismatch")


# --- pin_baseline: write-once -----------------------------------------------


def test_pin_writes_and_roundtrips_new_fields() -> None:
    """pin then load reconstructs dataset_hash and scorer_version."""
    result = run_delta(
        _dataset(), _naive(), _method(), _predict_fn, _scorer_fn, scorer_version="v1"
    )
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "baseline.json")
    try:
        pin_baseline(result, path)
        loaded = load_baseline(path)
    finally:
        if os.path.exists(path):
            os.remove(path)
        os.rmdir(tmpdir)
    assert loaded.dataset_hash == result.dataset_hash
    assert loaded.scorer_version == result.scorer_version
    assert loaded.format_version == result.format_version


def test_pin_refuses_overwrite_then_allows_explicit() -> None:
    """A second pin to a non-empty path raises; overwrite=True replaces it."""
    result = run_delta(
        _dataset(), _naive(), _method(), _predict_fn, _scorer_fn, scorer_version="v1"
    )
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, "baseline.json")
    try:
        pin_baseline(result, path)  # first write: ok
        raised = False
        try:
            pin_baseline(result, path)  # second write: refused
        except FileExistsError:
            raised = True
        assert raised, "expected FileExistsError on overwrite of a non-empty pin"
        # Explicit override succeeds.
        pin_baseline(result, path, overwrite=True)
    finally:
        if os.path.exists(path):
            os.remove(path)
        os.rmdir(tmpdir)


def test_pin_allows_empty_placeholder() -> None:
    """An empty placeholder file (e.g. mkstemp) is not a baseline; pin succeeds."""
    result = run_delta(
        _dataset(), _naive(), _method(), _predict_fn, _scorer_fn, scorer_version="v1"
    )
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)  # leaves a zero-byte file in place
    try:
        pin_baseline(result, path)  # size 0 -> allowed
        loaded = load_baseline(path)
        assert loaded.dataset_hash == result.dataset_hash
    finally:
        os.remove(path)


# --- load_baseline: legacy tolerance ----------------------------------------


def test_load_legacy_v1_fills_sentinels() -> None:
    """A v1 baseline with no hash/version loads with the non-comparable sentinels."""
    payload = {
        "model_label": "frontier-2026.06",
        "dataset_fingerprint": "corpus-v1",
        "naive_metrics": {"recall": 0.0},
        "method_metrics": {"recall": 1.0},
        "delta": {"recall": 1.0},
        "format_version": 1,
    }
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        loaded = load_baseline(path)
    finally:
        os.remove(path)
    assert loaded.dataset_hash == DATASET_HASH_UNHASHED
    assert loaded.scorer_version == SCORER_VERSION_UNSET


def test_legacy_baseline_must_be_repinned_before_compare() -> None:
    """A legacy (sentinel-hash) baseline cannot be silently differenced.

    The fresh run has a real content hash; the legacy baseline has the sentinel,
    so the gate raises -- forcing a re-pin rather than a misleading comparison.
    """
    legacy_payload = {
        "model_label": "frontier-2026.06",
        "dataset_fingerprint": "corpus-v1",
        "naive_metrics": {"recall": 0.0},
        "method_metrics": {"recall": 1.0},
        "delta": {"recall": 1.0},
        "format_version": 1,
    }
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(legacy_payload, fh)
        legacy = load_baseline(path)
    finally:
        os.remove(path)
    fresh = run_delta(_dataset(), _naive(), _method(), _predict_fn, _scorer_fn, scorer_version="v1")
    try:
        delta_vs_baseline(fresh, legacy)
    except ValueError as exc:
        assert "corpus mismatch" in str(exc)
        return
    raise AssertionError("expected ValueError differencing against a legacy baseline")


# --- scorer_source_version --------------------------------------------------


def test_scorer_source_version_deterministic_and_sensitive() -> None:
    """The tag is stable for fixed content and changes when content changes."""
    fd, path = tempfile.mkstemp(suffix=".py")
    os.close(fd)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("def score(): return 1\n")
        v1 = scorer_source_version(path)
        v1_again = scorer_source_version(path)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("def score(): return 2\n")
        v2 = scorer_source_version(path)
    finally:
        os.remove(path)
    assert v1 == v1_again
    assert v1 != v2
    assert v1.startswith("sha256:")


def test_scorer_source_version_requires_a_path() -> None:
    """Calling with no source paths is a programming error."""
    try:
        scorer_source_version()
    except ValueError:
        return
    raise AssertionError("expected ValueError when no source paths are given")


def test_scorer_source_version_order_matters() -> None:
    """File order is part of the tag (the domain separator makes it unambiguous)."""
    fd_a, path_a = tempfile.mkstemp(suffix=".py")
    os.close(fd_a)
    fd_b, path_b = tempfile.mkstemp(suffix=".py")
    os.close(fd_b)
    try:
        with open(path_a, "w", encoding="utf-8") as fh:
            fh.write("AAA\n")
        with open(path_b, "w", encoding="utf-8") as fh:
            fh.write("BBB\n")
        ab = scorer_source_version(path_a, path_b)
        ba = scorer_source_version(path_b, path_a)
    finally:
        os.remove(path_a)
        os.remove(path_b)
    assert ab != ba


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
